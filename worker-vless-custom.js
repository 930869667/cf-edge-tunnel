import { connect } from "cloudflare:sockets";

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

export default {
  /**
   * Worker 入口函数：负责路由分流（订阅下发、WebSocket 转发）
   */
  async fetch(request, env) {
    try {
      // If env.USER_ID is undefined, an empty string, or missing, the expression evaluates to null
      const userId = (env.USER_ID || null)?.trim()?.toLowerCase();
      // Cloudflare 反代IP <ipv4 or domain>, 为了简化处理，默认port 443，不支持其他port
      const proxyIp = (env.PROXY_IP || null)?.trim();
      // Cloudflare 优选IP：<ipv4 or domain,ipv4 or domain,...>， port是本站port 443
      const cfIpList = (env.CF_IP_LIST || null)?.trim();

      if (!userId || !isValidUUID(userId)) {
        throw new Error("Invalid UUID format");
      }
      const upgradeHeader = request.headers.get("Upgrade") || null;
      const url = new URL(request.url);
      // 去掉尾部斜杠，方便比较路由是否一致
      const normalizedPath = url.pathname.replace(/\/+$/, "");

      // =========================================================================
      // 1. 动态订阅处理逻辑 (拦截特定路径，如 /sub 或使用内置 UUID 作为路径)
      // =========================================================================
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
            "Cache-Control": "no-store",
          },
        });
      }

      // =========================================================================
      // 2. WebSocket 代理vless流量处理
      // =========================================================================
      if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
        return await vlessOverWSHandler(request, userId, proxyIp);
      }

      // =========================================================================
      // 3. 静态伪装机制：既不是订阅也不是 WS，返回页面
      // =========================================================================
      return new Response("404 Not Found", { status: 404 });
    } catch (err) {
      console.error(`[服务器内部错误] fetch 流程阻断: ${err.message}`);
      return new Response(`Internal Server Error`, { status: 500 });
    }
  },
};

function generateSub(cfIpList, userId, hostName) {
  // 客户端（v2rayN/Shadowrocket）默认下发 Base64 编码的 VLESS 节点链接
  if (!cfIpList) return "";
  const sub = cfIpList
    .split(",")
    .map((ip) => ip.trim())
    .map(
      (ip) =>
        `vless://${userId}@${ip}:443?type=ws&security=tls&host=${hostName}&fp=chrome&path=%2F%3Fed%3D2048&sni=${hostName}#${encodeURIComponent("Cloudflare-" + ip)}`,
    )
    .join("\n");
  return btoa(sub);
}

async function vlessOverWSHandler(request, userId, proxyIp, proxyPort = 443) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || null;

  const readableWebSocketStream = makeReadableWebSocketStream(
    webSocket,
    earlyDataHeader,
  );

  let remoteSocketWrapper = {
    value: null,
  };
  let udpStreamWrite = null;
  let isDns = false;

  // ws --> remote
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = processVlessHeader(chunk, userId);
          // if UDP but port not DNS port, close it
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              // controller.error('UDP proxy only enable for DNS which is port 53');
              throw new Error("UDP proxy only enable for DNS which is port 53"); // cf seems has bug, controller.error will not end stream
            }
          }

          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            const { write } = await handleUDPOutbound(
              webSocket,
              vlessResponseHeader,
            );
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          try {
            await handleTCPOutBound(
              remoteSocketWrapper,
              addressRemote,
              portRemote,
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

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

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
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;

    const writer = tcpSocket.writable.getWriter();
    try {
      await writer.write(rawClientData); // first write, nomal is tls client hello
    } finally {
      writer.releaseLock();
    }
    return tcpSocket;
  }

  // if the cf connect tcp socket have no incoming data, we retry to redirect ip
  async function retry() {
    if (!proxyIp || !proxyPort) {
      throw new Error("retry failed, proxyIp or proxyPort is not set");
    }
    // 关键修复：主动关闭之前的直连 Socket, 避免资源泄漏和潜在的连接冲突
    if (remoteSocket.value) {
      try {
        remoteSocket.value.close();
      } catch (err) {
        console.error(`close original socket error: ${err.message}`);
      }
    }
    const tcpSocket = await connectAndWrite(proxyIp, proxyPort);
    // no matter retry success or not, close websocket
    tcpSocket.closed
      .catch((err) => {
        console.error(`retry tcpSocket closed error, ${err}`);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  // when remoteSocket is ready, pass to websocket
  // remote--> ws
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
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

      // for ws 0rtt
      const earlyData = base64ToArrayBuffer(earlyDataHeader);
      if (earlyData) {
        if (earlyData.byteLength > 4 * 1024) {
          throw new Error("earlyDataHeader is too large, max 4KB");
        }
        // enqueue 尽量保障捕获异常
        try {
          controller.enqueue(earlyData);
        } catch (err) {
          console.error(`enqueue earlyData error: ${err.message}`);
        }
      }
    },

    pull(controller) {
      // if ws can stop read if stream is full, we can implement backpressure
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

function processVlessHeader(vlessBuffer, userId) {
  const buffer =
    vlessBuffer instanceof Uint8Array
      ? vlessBuffer
      : new Uint8Array(vlessBuffer);

  if (buffer.byteLength < 24) {
    throw new Error("invalid data: buffer length is less than 24 bytes");
  }
  // 1. 读取协议版本号
  const version = buffer.slice(0, 1);

  let isUDP = false;
  // 2. 校验 UUID 身份令牌
  if (stringify(buffer.slice(1, 17)) !== userId) {
    throw new Error("invalid data: UUID does not match");
  }

  const optLength = buffer[17];

  // 3. 读取传输指令类型 (0x01 TCP, 0x02 UDP)
  const commandIndex = 18 + optLength;
  if (buffer.byteLength < commandIndex + 1) {
    throw new Error("invalid data: command out of range");
  }
  const command = buffer[commandIndex];

  // 0x01 TCP
  // 0x02 UDP
  // 0x03 MUX
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    throw new Error(
      `invalid data: command is ${command}, only support TCP or UDP`,
    );
  }
  const portIndex = commandIndex + 1;
  if (buffer.byteLength < portIndex + 2) {
    throw new Error("invalid data: port out of range");
  }
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  // port is big-Endian in raw data etc 80 == 0x005d
  const portRemote = new DataView(
    portBuffer.buffer,
    portBuffer.byteOffset,
    portBuffer.byteLength,
  ).getUint16(0);

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
    case 1:
      addressLength = 4;
      if (buffer.byteLength < addressValueIndex + addressLength) {
        throw new Error("invalid data: ipv4 address out of range");
      }
      addressValue = buffer
        .slice(addressValueIndex, addressValueIndex + addressLength)
        .join(".");
      break;
    case 2:
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
      addressValue = new TextDecoder().decode(
        buffer.slice(addressValueIndex, addressValueIndex + addressLength),
      );
      break;
    case 3:
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
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

async function remoteSocketToWS(
  remoteSocket,
  webSocket,
  vlessResponseHeader,
  retry,
) {
  // remote--> ws

  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false; // check if remoteSocket has incoming data

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},

        async write(chunk, controller) {
          hasIncomingData = true;
          // remoteChunkCount++;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            safeCloseWebSocket(webSocket);
            controller.error("webSocket.readyState is not open, maybe close");
            return;
          }
          try {
            if (vlessHeader) {
              // With zero-async ArrayBuffer allocation:
              const combined = new Uint8Array(
                vlessHeader.byteLength + chunk.byteLength,
              );
              combined.set(new Uint8Array(vlessHeader), 0);
              combined.set(chunk, vlessHeader.byteLength);
              webSocket.send(combined.buffer);
              vlessHeader = false;
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
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort ${reason}`);
        },
      }),
    )
    .catch((err) => {
      console.error(`remoteSocketToWS has exception ${err}`);
      safeCloseWebSocket(webSocket);
    });

  // seems is cf connect socket have error,
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

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return null;
  try {
    // go use modified Base64 for URL rfc4648 which js atob not support
    const binary = atob(base64Str.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch (err) {
    console.error(`base64 decode error: ${err.message}`);
    return null; // 发生非法字符解析失败时返回 null，避免直接崩溃退出);
  }
}

function isValidUUID(uuid) {
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === WS_READY_STATE_OPEN ||
      socket.readyState === WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (err) {
    console.error(`safeCloseWebSocket error: ${err.message}`);
  }
}

function unsafeStringify(arr, offset = 0) {
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
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw new Error(`Invalid UUID format: ${uuid}`);
  }
  return uuid;
}

async function handleUDPOutbound(webSocket, vlessResponseHeader) {
  let isVlessHeaderSent = false;
  let pendingUdpData = new Uint8Array(0); // Store pending UDP data

  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      const nextBuffer = concatUint8Arrays([
        pendingUdpData,
        new Uint8Array(chunk),
      ]);
      let offset = 0;
      while (offset + 2 <= nextBuffer.length) {
        const udpPacketLength = new DataView(
          nextBuffer.buffer,
          nextBuffer.byteOffset + offset,
          2,
        ).getUint16(0);
        const totalPacketSize = 2 + udpPacketLength;
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

  // only handle dns udp for now
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const abortController = new AbortController();
          const timeoutId = setTimeout(() => {
            abortController.abort("dns query timeout");
          }, 5000); // 5 seconds timeout
          let dnsQueryResult;
          try {
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
            clearTimeout(timeoutId);
          }

          const udpSize = dnsQueryResult.byteLength;

          const udpSizeBuffer = new Uint8Array([
            (udpSize >> 8) & 0xff,
            udpSize & 0xff,
          ]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            console.log(`doh success and dns message length is ${udpSize}`);
            try {
              if (isVlessHeaderSent) {
                webSocket.send(
                  await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer(),
                );
              } else {
                webSocket.send(
                  await new Blob([
                    vlessResponseHeader,
                    udpSizeBuffer,
                    dnsQueryResult,
                  ]).arrayBuffer(),
                );
                isVlessHeaderSent = true;
              }
            } catch (err) {
              console.error(
                `handleUDPOutbound send to ws error: ${err.message}`,
              );
              safeCloseWebSocket(webSocket);
            }
          }
        },
      }),
    )
    .catch((err) => {
      //当 Fetch 请求超时（abort）或遇到其他异常抛出时，进入此 catch
      console.error(`handleUDPOutbound pipeTo has exception ${err.message}`);
      safeCloseWebSocket(webSocket);

      // 增加此处的修复：主动释放/中断 writer，防止 TransformStream 管道挂起
      try {
        writer.abort(err);
      } catch (e) {
        // 忽略已关闭的 writer 报错
      }
    });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}
