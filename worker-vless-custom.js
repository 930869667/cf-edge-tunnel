import { connect } from "cloudflare:sockets";

/**
 * WebSocket 握手状态码定义 (符合 RFC 6455 规范)
 * 1 (OPEN): 连接已建立，可双向传输 Frame
 * 2 (CLOSING): 正在执行 Close 帧握手
 */
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

// =========================================================================
// 1. Worker 入口模块 (HTTP 伪装/路由分发/订阅下发)
// =========================================================================
export default {
  /**
   * Cloudflare Worker 无服务器架构主入口
   *
   * 【背压与生命周期机制】：
   * Worker 运行在 V8 隔离环境（Isolate）中，受限于 strict CPU Time（如 10ms-50ms）。
   * 但对于 Stream 传输，Worker 采用异步 I/O 挂起机制，只要 Pipe Stream 保持活跃，
   * 运行环境就不会被系统回收，从而实现长连接代理。
   */
  async fetch(request, env) {
    try {
      // 提取并清洗环境变量（USER_ID: 身份鉴权密钥; PROXY_IP: 备用回退反代 IP; CF_IP_LIST: 优选节点列表）
      const userId = (env.USER_ID || null)?.trim()?.toLowerCase();
      // Cloudflare 反代IP <ipv4 or domain>, 为了简化处理，默认port 443，不支持其他port
      const proxyIp = (env.PROXY_IP || null)?.trim();
      // Cloudflare 优选IP：<ipv4 or domain,ipv4 or domain,...>， port是本站port 443
      const cfIpList = (env.CF_IP_LIST || null)?.trim();

      // 安全防御机制：未设置合法 UUID 时直接熔断，防止非法/越权握手
      if (!userId || !isValidUUID(userId)) {
        throw new Error("Invalid UUID format");
      }
      const upgradeHeader = request.headers.get("Upgrade") || null;
      const url = new URL(request.url);
      // 去掉尾部斜杠，方便比较路由是否一致
      const normalizedPath =
        url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/, "");

      // 1.1 动态节点订阅下发 (匹配暗号路径: /{UUID}/vE4pQ9xN2k)
      // 原理：客户端（如 v2rayN, Shadowrocket）通过 GET 请求拉取配置，服务端动态组合优选 IP 列表下发
      if (
        request.method === "GET" &&
        normalizedPath === `/${userId}/vE4pQ9xN2k`
      ) {
        // 当前 Worker 绑定的自定义域名
        const hostName = url.hostname;
        const subscription = generateSub(cfIpList, userId, hostName);

        return new Response(subscription, {
          status: 200,
          headers: {
            "Content-Type": "text/plain;charset=utf-8",
            "Cache-Control": "no-store", // 强制禁用边缘节点与客户端缓存，确保 IP 列表实时更新
          },
        });
      }

      // 1.2 WebSocket 代理流量接管
      // 原理：检查 HTTP Header 是否包含 Upgrade: websocket，若存在则将 HTTP 协议升级为全双工 WebSocket
      if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
        return await handleVlessOverWS(request, userId, proxyIp);
      }

      // 1.3 静态伪装防御机制
      // 深度主动探测防护：当主动扫描器（如 GFW 主动探测）发送普通 HTTP GET/POST 时，
      // 返回标准 404 伪装成普通不存在的静态页面，屏蔽代理节点协议特征。
      return new Response("404 Not Found", { status: 404 });
    } catch (err) {
      console.error(`[服务器内部错误] fetch 流程阻断: ${err.message}`);
      return new Response(`Internal Server Error`, { status: 500 });
    }
  },
};

/**
 * 动态生成 Base64 编码的 VLESS 订阅节点配置格式
 * 原理：将每一个优选 IP 按照 VLESS 协议的标准 URI 格式拼接，再进行统一 Base64 编码输出
 */
function generateSub(cfIpList, userId, hostName) {
  // 客户端（v2rayN/Shadowrocket）默认下发 Base64 编码的 VLESS 节点链接
  if (!cfIpList) return "";
  const lines = cfIpList
    .split(",")
    .map((ip) => ip.trim())
    .map(
      (ip) =>
        `vless://${userId}@${ip}:443?type=ws&security=tls&host=${hostName}&fp=chrome&path=%2F%3Fed%3D2048&sni=${hostName}#${encodeURIComponent("Cloudflare-" + ip)}`,
    );
  return btoa(lines.join("\n"));
}

// =========================================================================
// 2. WS 流量调度模块 (VLESS WebSocket Handler)
// =========================================================================
async function handleVlessOverWS(request, userId, proxyIp, proxyPort = 443) {
  // 建立双向 WebSocket 管道（client 暴露给客户端，webSocket 由 Worker 内部掌控）
  const [client, webSocket] = Object.values(new WebSocketPair());

  webSocket.accept(); // 完成 WebSocket 协议握手切换

  /**
   * WS 0-RTT (Early Data) 优化原理：
   * 传统 WS 握手需要 1 个 RTT，TCP 握手 1 个 RTT。
   * 支持 EarlyData 时，客户端在 HTTP Upgrade 请求头的 `sec-websocket-protocol` 中
   * 以 Base64 形式直接带上 VLESS 首包数据，从而省去 1 个 RTT 延时。
   */
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || null;
  if (earlyDataHeader && earlyDataHeader.length > 8192) {
    throw new Error("EarlyData header too large");
  }
  const readableWebSocketStream = createWSReadableStream(
    webSocket,
    earlyDataHeader,
  );

  // 状态闭包变量：在不同的 chunk 写入周期中保持 TCP 管道与 UDP 模式的状态记录
  let remoteSocketWrapper = {
    value: null,
  };
  let udpWriter = null;
  let isDnsMode = false;

  // ws --> remote
  // 使用 WHATWG Streams API 将 WebSocket 可读流对接至可写处理流
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          // 【分支 1】：UDP DNS 模式
          // 若之前已识别为 DNS 请求（UDP Port 53），后续所有二进制块均直接送入 DoH 处理模块
          if (isDnsMode && udpWriter) {
            return udpWriter(chunk);
          }
          // 【分支 2】：TCP 直连建立后的常态化转发
          // 当与远端服务器的 TCP 物理 Socket 已建立，后续的所有客户端 Payload 绕过 Header 解析，直接写入 Socket
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock(); // 极其重要：必须及时释放 Stream 锁，防止下一步管道锁死
            return;
          }

          // 【分支 3】：首包解析 (VLESS Header Decapsulation)
          // 解包客户端发送的第一帧数据，提取并校验 UUID，并获取真正的远程连接目标 (Domain/IP:Port)
          const header = processVlessHeader(chunk, userId);
          const rawClientData = chunk.slice(header.rawDataIndex); // 截取除去 VLESS 头后的真实 payload
          const vlessResponseHeader = new Uint8Array([
            header.vlessVersion[0],
            0,
          ]); // 构造 VLESS 握手响应头

          // 校验传输层协议类型 (UDP / TCP)
          if (header.isUDP) {
            // 安全限制：基于 Cloudflare Worker 的无状态 Serverless 特性，
            // 目前 UDP 代理仅支持 53 端口的 DNS 报文转发（转换为 DoH）
            if (header.portRemote !== 53) {
              throw new Error(
                "UDP proxy is strictly disabled except for DNS (port 53)",
              );
            }
            isDnsMode = true;
            const udpHandler = await createUDPHandler(
              webSocket,
              vlessResponseHeader,
            );
            udpWriter = udpHandler.write;
            udpWriter(rawClientData); // 发送首包中包含的 DNS 查询请求
            return;
          }

          // 执行 TCP 物理连接建立与管道转发
          try {
            await handleTCPOutBound(
              remoteSocketWrapper,
              header.addressRemote,
              header.portRemote,
              proxyIp,
              proxyPort,
              rawClientData,
              webSocket,
              vlessResponseHeader,
            );
          } catch (err) {
            console.error(`handleTCPOutBound error: ${err.message}`);
            safeCloseWebSocket(webSocket);
            controller.error(err);
          }
        },
        close() {
          console.log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          console.log(`readableWebSocketStream is abort, ${reason}`);
        },
      }),
    )
    .catch((err) => {
      console.error(`readableWebSocketStream pipeTo has exception: ${err}`);
      safeCloseWebSocket(webSocket);
    });

  // 返回 101 HTTP Status Code，完成与客户端的 WebSocket 握手回应
  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

// =========================================================================
// 3. TCP 转发模块 (TCP Outbound Proxy & Fallback Retry)
// =========================================================================
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  proxyIp,
  proxyPort,
  rawClientData,
  webSocket,
  vlessResponseHeader,
) {
  /**
   * 使用 Cloudflare 原生 Socket API (`cloudflare:sockets`) 建立出站连接
   * 原理：直接在 Cloudflare 边缘节点发起底层 TCP 三次握手，避开传统 HTTP 代理的额外开销
   */
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });

    const writer = tcpSocket.writable.getWriter();
    try {
      await writer.write(rawClientData); // 写入首包数据（通常是 TLS Client Hello 或 HTTP 请求）
    } catch (err) {
      try {
        tcpSocket.close();
      } catch {
        console.error(`close tcpSocket error: ${err.message}`);
      }
      throw new Error(`connectAndWrite failed, ${err.message}`);
    } finally {
      writer.releaseLock();
    }
    remoteSocket.value = tcpSocket;

    return tcpSocket;
  }

  /**
   * 回退重试逻辑 (Fallback Retry)
   * 原理：当直连目标服务器超时、被封锁或阻断时，自动切换连接至预先配置的 PROXY_IP 反代节点。
   */
  async function retry() {
    if (!proxyIp || !proxyPort) {
      throw new Error("retry failed, proxyIp or proxyPort is not set");
    }
    // 【核心修复防泄漏】：在重新创建连接前，必须手动调用 close() 关闭此前因网络阻断挂起的直连 Socket，
    // 释放 Cloudflare 边缘节点底层 Socket 连接池句柄，防止内存与连接数暴涨。
    if (remoteSocket.value) {
      try {
        remoteSocket.value.close();
      } catch (err) {
        console.error(`close original socket error: ${err.message}`);
      }
    }
    // 连接至中转 PROXY_IP
    const tcpSocket = await connectAndWrite(proxyIp, proxyPort);
    // no matter retry success or not, close websocket
    tcpSocket.closed
      .catch((err) => {
        console.error(`retry tcpSocket closed error, ${err}`);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    pipeRemoteToWS(tcpSocket, webSocket, vlessResponseHeader, null); // 重试管道不再挂载二次 retry
  }

  // 优先尝试直连目标主机 (Client -> Target Server)
  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  pipeRemoteToWS(tcpSocket, webSocket, vlessResponseHeader, retry);
}

/**
 * 将远程 TCP Socket 返回的数据传输回 WebSocket (remoteSocket -> WebSocket)
 *
 * 【背压机制与流调优】：
 * 使用 pipeTo 自动处理传输速率不匹配问题。若客户端网络卡顿，pipeTo 会自动暂停从底层 Socket 读取数据，
 * 避免无限堆积内存导致 Worker 爆内存（OOM）。
 */
async function pipeRemoteToWS(
  remoteSocket,
  webSocket,
  vlessResponseHeader,
  retry,
) {
  // remote--> ws

  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false; // 标记位：记录目标服务端是否有任何字节数据返回
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},

        async write(chunk, controller) {
          hasIncomingData = true; // 只要有任何数据返回，即证明直连成功
          // remoteChunkCount++;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            safeCloseWebSocket(webSocket);
            controller.error("webSocket.readyState is not open, maybe close");
            return;
          }
          try {
            /**
             * VLESS 协议响应规范：
             * 在连接成功后的【第一帧数据包】头部，必须携带 2 字节的响应报头 `[VLESS_VERSION, 0]`。
             * 后续的数据包则直接透传 Payload。
             */
            if (vlessHeader) {
              // With zero-async ArrayBuffer allocation:
              const combined = new Uint8Array(
                vlessHeader.byteLength + chunk.byteLength,
              );
              combined.set(new Uint8Array(vlessHeader), 0);
              combined.set(chunk, vlessHeader.byteLength);
              webSocket.send(combined.buffer);
              vlessHeader = null; // 发送完成后清空 Header，不再重复追加
            } else {
              webSocket.send(chunk);
            }
          } catch (err) {
            controller.error(err);
            safeCloseWebSocket(webSocket);
          }
        },
        close() {
          console.log(
            `remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`,
          );
          if (hasIncomingData) {
            safeCloseWebSocket(webSocket);
          }
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort ${reason}`);
        },
      }),
    )
    .catch((err) => {
      console.error(`pipeRemoteToWS has exception ${err.message}`);
      safeCloseWebSocket(webSocket);
      throw new Error(`pipeRemoteToWS has exception ${err.message}`);
    });

  // 触发重试逻辑的关键条件：连接已断开 + 从未收到过远端数据 + 挂载了重试函数
  // 1. Socket.closed will have error
  // 2. Socket.readable will be close without any data coming
  if (hasIncomingData === false && retry) {
    try {
      await retry();
    } catch (err) {
      console.error(`retry failed, ${err.message}`);
      safeCloseWebSocket(webSocket);
    }
  }
}

/**
 * 将 WebSocket 原生事件流封装为标准 Web API ReadableStream 管道
 */
function createWSReadableStream(webSocketServer, earlyDataHeader) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      // 监听客户端发送的数据帧
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;

        const message = event.data;

        if (message instanceof ArrayBuffer) {
          controller.enqueue(new Uint8Array(message));
        } else if (message instanceof Uint8Array) {
          controller.enqueue(message);
        } else if (message instanceof Blob) {
          message
            .arrayBuffer()
            .then((buffer) => {
              if (readableStreamCancel) {
                return;
              }
              controller.enqueue(new Uint8Array(buffer));
            })
            .catch((err) => {
              controller.error(err);
            });
        } else {
          controller.error(`WebSocket message must be binary`);
        }
      });

      // 监听 TCP/WS 断开关闭
      // The event means that the client closed the client -> server stream.
      // However, the server -> client stream is still open until you call close() on the server side.
      // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
      webSocketServer.addEventListener("close", () => {
        // client send close, need close server
        // if stream is cancel, skip controller.close
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });

      webSocketServer.addEventListener("error", (err) => {
        console.error("webSocketServer has error", err);
        controller.error(err);
      });

      // 提取并注入 WS 0-RTT EarlyData 首包
      const earlyData = base64ToArrayBuffer(earlyDataHeader);
      if (earlyData) {
        // enqueue 尽量保障捕获异常
        try {
          controller.enqueue(earlyData);
        } catch (err) {
          console.error(`enqueue earlyData error: ${err.message}`);
        }
      }
    },

    pull(controller) {
      // Streams API provides downstream backpressure, but WebSocket event source itself cannot be paused directly.
      // https://streams.spec.whatwg.org/#example-rs-push-backpressure
    },
    cancel(reason) {
      // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
      // 2. if readableStream is cancel, all controller.close/enqueue need skip,
      // 3. but from testing controller.error still work even if readableStream is cancel
      if (readableStreamCancel) {
        return;
      }
      console.log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

// =========================================================================
// 5. VLESS 协议二进制报文解析模块 (Binary Protocol Parser)
// =========================================================================
function processVlessHeader(vlessBuffer, userId) {
  /**
   * VLESS 协议首包报文结构 (VLESS Request Packet Format):
   * +-----+-------------------------------+-------------------+----------+----------+----------+-------------------+
   * | VER |            UUID               | M (Add Opt Length)| M Length | COMMAND  | PORT     | ADDR TYPE         |
   * | 1B  |            16B                |       1B          |    MB    |   1B     |  2B      |    1B             |
   * +-----+-------------------------------+-------------------+----------+----------+----------+-------------------+
   * | ADDR (Variable Length)              | PAYLOAD (Client Data ...)                                              |
   * +-------------------------------------+------------------------------------------------------------------------+
   *
   * ADDRESS TYPE 细节说明:
   * 0x01: IPv4 (4 字节)
   * 0x02: Domain (域名，首字节为域名长度 Length，后跟 N 字节 ASCII 字符串)
   * 0x03: IPv6 (16 字节)
   *
   * COMMAND 细节说明:
   * 0x01: TCP 代理
   * 0x02: UDP 代理
   * 0x03: Mux (多路复用，目前暂不支持)
   */
  const buffer =
    vlessBuffer instanceof Uint8Array
      ? vlessBuffer
      : new Uint8Array(vlessBuffer);

  if (buffer.byteLength < 24) {
    throw new Error("invalid data: buffer length is less than 24 bytes");
  }
  // 1. 协议版本 (Version), 不需要校验
  const version = buffer[0];

  // 2. 身份校验 (1-16 字节为 UUID)
  if (byteToUUID(buffer.slice(1, 17)) !== userId) {
    throw new Error("Authentication failed: UUID mismatch");
  }

  // 3. 动态偏移量计算 (跳过附加选项 Opt)
  const optLength = buffer[17];
  if (18 + optLength > buffer.byteLength) {
    throw new Error("invalid data: option length out of range");
  }

  // 3. 读取传输指令类型 (0x01 TCP, 0x02 UDP)
  const commandIndex = 18 + optLength;
  if (buffer.byteLength < commandIndex + 1) {
    throw new Error("invalid data: command out of range");
  }
  const command = buffer[commandIndex];
  const isUDP = command === 2;

  // 0x01 TCP
  // 0x02 UDP
  // 0x03 MUX
  if (command !== 1 && !isUDP) {
    throw new Error(
      `Unsupported VLESS command: 0x${command.toString(16)} (only TCP 0x01 and UDP 0x02 supported)`,
    );
  }

  // 4. 读取端口 (大端字节序 Big-Endian，高位在前，低位在后)
  const portIndex = commandIndex + 1;
  if (buffer.byteLength < portIndex + 2) {
    throw new Error("invalid data: port out of range");
  }
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  // port is big-Endian in raw data
  const portRemote = new DataView(
    portBuffer.buffer,
    portBuffer.byteOffset,
    portBuffer.byteLength,
  ).getUint16(0);

  // 5. 提取并解析目标地址
  let addressIndex = portIndex + 2;
  if (buffer.byteLength < addressIndex + 1) {
    throw new Error("invalid data: address type out of range");
  }
  const addressBuffer = buffer.slice(addressIndex, addressIndex + 1);

  // 1--> ipv4  addressLength =4
  // 2--> domain name addressLength=addressBuffer[1]
  // 3--> ipv6  addressLength =16
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1: // IPv4 格式: 逐字节点分十进制 192.168.1.1
      addressLength = 4;
      if (buffer.byteLength < addressValueIndex + addressLength) {
        throw new Error("invalid data: ipv4 address out of range");
      }
      addressValue = buffer
        .slice(addressValueIndex, addressValueIndex + addressLength)
        .join(".");
      break;
    case 2: // Domain 格式: 首字节为动态长度
      if (buffer.byteLength < addressValueIndex + 1) {
        throw new Error("invalid data: domain length out of range");
      }
      addressLength = buffer[addressValueIndex];
      addressValueIndex += 1;
      if (addressLength === 0) {
        throw new Error("invalid data: domain length is 0");
      }
      if (buffer.byteLength < addressValueIndex + addressLength) {
        throw new Error("invalid data: domain address out of range");
      }
      const decoder = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: false, // Add this line to satisfy the type definition
      });
      addressValue = decoder.decode(
        buffer.slice(addressValueIndex, addressValueIndex + addressLength),
      );
      break;
    case 3: // IPv6 格式: 16 字节拆分为 8 组 16 位 16 进制字符串
      addressLength = 16;
      if (buffer.byteLength < addressValueIndex + addressLength) {
        throw new Error("invalid data: ipv6 address out of range");
      }
      const dataView = new DataView(
        buffer.buffer,
        buffer.byteOffset + addressValueIndex,
        addressLength,
      );
      // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      // seems no need add [] for ipv6
      break;
    default:
      throw new Error("invalid data: unknown address type");
  }
  if (!addressValue) {
    throw new Error("invalid data: address value is empty");
  }

  return {
    vlessVersion: version,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    isUDP,
  };
}

/**
 * 内存分配优化版 Uint8Array 拼接工具
 * 原理：预先一次性分配目标大小内存，避免产生 Array 频繁扩容重排的开销
 */
function concatUint8Arrays(arrays) {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * 解码符合 RFC 4648 规范的 URL-Safe Base64 字符串
 * 原理：替换 `-` 为 `+`，`_` 为 `/`，兼容标准的 JS atob 函数
 */
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return null;
  try {
    const normalized = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch (err) {
    console.error(`base64 decode error: ${err.message}`);
    return null; // 发生非法字符解析失败时返回 null，避免直接崩溃退出
  }
}

/**
 * 基于标准 8-4-4-4-12 格式的正则 UUID 校验
 */
function isValidUUID(uuid) {
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * 防重复触发异常的 WebSocket 安全关闭函数
 */
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN) {
      socket.close();
    }
  } catch (err) {
    console.error(`safeCloseWebSocket error: ${err.message}`);
  }
}

/**
 * 将 16 字节的二进制数据（Byte Array）转换成标准 UUID（通用唯一识别码）字符串
 * 预先在内存中生成了一个名为 byteToHex 的数组，里面存好了 0 到 255 所有数字对应的
 * 16 进制字符串（即 ['00', '01', ..., 'ff']）, 转换时，直接通过下标取值（如 byteToHex[255]
 * 瞬间返回 'ff'）。用极小的内存空间，换取了接近 CPU 极限的查找速度
 */
function byteToUUID(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

// =========================================================================
// 4. UDP / DoH 处理模块 (DNS Over HTTPS Forwarder)
// =========================================================================
async function createUDPHandler(webSocket, vlessResponseHeader) {
  let isVlessHeaderSent = false;
  let pendingUdpData = new Uint8Array(0); // Store pending UDP data

  /**
   * UDP Over TCP/WS 数据包拆包原理：
   * 客户端发送 UDP 数据流时，为了在面向字节流的 TCP/WS 中区分不同的 UDP 数据报文，
   * VLESS 协议引入了长度打包机制：[2 字节 UDP 包长度 (Big-Endian)] + [UDP 数据 Payload]。
   *
   * TransformStream 的作用是将不连续的 WS 块重新拼接并精准拆分为一个个独立的 UDP 数据包。
   */
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      const nextBuffer = concatUint8Arrays([
        pendingUdpData,
        new Uint8Array(chunk),
      ]);
      let offset = 0;
      // 循环解析符合 [Length (2B)] + [Data (Length B)] 结构的包
      while (offset + 2 <= nextBuffer.length) {
        const udpPacketLength = new DataView(
          nextBuffer.buffer,
          nextBuffer.byteOffset + offset,
          2,
        ).getUint16(0);
        const totalPacketSize = 2 + udpPacketLength;
        // 若当前 buffer 剩余长度不足一个完整包，结束本次解析，留到下一个 chunk
        if (offset + totalPacketSize > nextBuffer.length) {
          pendingUdpData = nextBuffer.slice(offset);
          return;
        }
        const udpData = nextBuffer.slice(offset + 2, offset + totalPacketSize);
        controller.enqueue(udpData);
        offset += totalPacketSize;
      }
      if (offset < nextBuffer.length) {
        pendingUdpData = nextBuffer.slice(offset);
      } else {
        pendingUdpData = new Uint8Array(0);
      }
    },
    flush(controller) {},
  });

  // 消费切分好的 DNS 报文，转换为 DNS Over HTTPS (DoH) HTTP/2 请求
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const abortController = new AbortController();
          const timeoutId = setTimeout(() => {
            abortController.abort("dns query timeout");
          }, 5000); // 设置 5 秒 DNS 请求超时 limit
          let dnsQueryResult;
          try {
            // 通过 HTTP/2 POST 将纯二进制 DNS 报文推送到 Cloudflare 官方 DoH 接口 (1.1.1.1)
            const resp = await fetch("https://1.1.1.1/dns-query", {
              method: "POST",
              headers: {
                "content-type": "application/dns-message",
              },
              body: chunk,
              signal: abortController.signal,
            });
            if (!resp.ok) {
              throw new Error(`DNS query failed with status ${resp.status}`);
            }
            dnsQueryResult = await resp.arrayBuffer();
          } finally {
            clearTimeout(timeoutId); // 释放定时器句柄，防止内存泄露
          }

          // 重新组装 VLESS UDP 返回帧格式：[2 字节 UDP 长度] + [DNS 回应 Payload]
          // UDP length field is 2 bytes, so maximum is 65535
          if (dnsQueryResult.byteLength > 65535) {
            throw new Error(
              `DNS response too large: ${dnsQueryResult.byteLength}`,
            );
          }

          const dnsResponse = new Uint8Array(dnsQueryResult);
          const udpSize = dnsResponse.byteLength;

          const udpSizeBuffer = new Uint8Array([
            (udpSize >> 8) & 0xff,
            udpSize & 0xff,
          ]);
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            return;
          }

          console.log(`doh success and dns message length is ${udpSize}`);
          try {
            const responseParts = [];
            // VLESS response header is sent only once.
            if (!isVlessHeaderSent) {
              responseParts.push(vlessResponseHeader);
            }
            // VLESS UDP response: // [2 bytes UDP length] + [UDP payload]
            responseParts.push(udpSizeBuffer, dnsResponse);
            const response = concatUint8Arrays(responseParts);
            webSocket.send(response.buffer);
            isVlessHeaderSent = true;
          } catch (err) {
            console.error(`createUDPHandler send to ws error: ${err.message}`);
            safeCloseWebSocket(webSocket);
            throw new Error(
              `createUDPHandler send to ws error: ${err.message}`,
            );
          }
        },
      }),
    )
    .catch((err) => {
      //当 Fetch 请求超时（abort）或遇到其他异常抛出时，进入此 catch
      console.error(`createUDPHandler pipeTo has exception ${err.message}`);
      safeCloseWebSocket(webSocket);
    });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      return writer.write(chunk);
    },
    close() {
      return writer.close();
    },
    abort(reason) {
      return writer.abort(reason);
    },
  };
}
