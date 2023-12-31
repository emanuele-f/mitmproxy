"""
This module defines "server instances", which manage
the TCP/UDP servers spawned by mitmproxy as specified by the proxy mode.

Example:

    mode = ProxyMode.parse("reverse:https://example.com")
    inst = ServerInstance.make(mode, manager_that_handles_callbacks)
    await inst.start()
    # TCP server is running now.
"""
from __future__ import annotations

import asyncio
import errno
import json
import logging
import os
import socket
import sys
import textwrap
import typing
from abc import ABCMeta
from abc import abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import cast
from typing import ClassVar
from typing import Generic
from typing import get_args
from typing import TYPE_CHECKING
from typing import TypeVar

from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import platform
from mitmproxy.connection import Address
from mitmproxy.net import local_ip
from mitmproxy.net import udp
from mitmproxy.proxy import commands
from mitmproxy.proxy import layers
from mitmproxy.proxy import mode_specs
from mitmproxy.proxy import server
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layer import Layer
from mitmproxy.utils import human

if sys.version_info < (3, 11):
    from typing_extensions import Self  # pragma: no cover
else:
    from typing import Self

if TYPE_CHECKING:
    from mitmproxy.master import Master

logger = logging.getLogger(__name__)


class ProxyConnectionHandler(server.LiveConnectionHandler):
    master: Master

    def __init__(self, master, r, w, options, mode):
        self.master = master
        super().__init__(r, w, options, mode)
        self.log_prefix = f"{human.format_address(self.client.peername)}: "

    async def handle_hook(self, hook: commands.StartHook) -> None:
        with self.timeout_watchdog.disarm():
            # We currently only support single-argument hooks.
            (data,) = hook.args()
            await self.master.addons.handle_lifecycle(hook)
            if isinstance(data, flow.Flow):
                await data.wait_for_resume()  # pragma: no cover


M = TypeVar("M", bound=mode_specs.ProxyMode)


class ServerManager(typing.Protocol):
    # temporary workaround: for UDP, we use the 4-tuple because we don't have a uuid.
    connections: dict[tuple | str, ProxyConnectionHandler]

    @contextmanager
    def register_connection(
        self, connection_id: tuple | str, handler: ProxyConnectionHandler
    ):
        ...  # pragma: no cover


class ServerInstance(Generic[M], metaclass=ABCMeta):
    __modes: ClassVar[dict[str, type[ServerInstance]]] = {}

    last_exception: Exception | None = None

    def __init__(self, mode: M, manager: ServerManager):
        self.mode: M = mode
        self.manager: ServerManager = manager

    def __init_subclass__(cls, **kwargs):
        """Register all subclasses so that make() finds them."""
        # extract mode from Generic[Mode].
        mode = get_args(cls.__orig_bases__[0])[0]  # type: ignore
        if not isinstance(mode, TypeVar):
            assert issubclass(mode, mode_specs.ProxyMode)
            assert mode.type_name not in ServerInstance.__modes
            ServerInstance.__modes[mode.type_name] = cls

    @classmethod
    def make(
        cls,
        mode: mode_specs.ProxyMode | str,
        manager: ServerManager,
    ) -> Self:
        if isinstance(mode, str):
            mode = mode_specs.ProxyMode.parse(mode)
        inst = ServerInstance.__modes[mode.type_name](mode, manager)

        if not isinstance(inst, cls):
            raise ValueError(f"{mode!r} is not a spec for a {cls.__name__} server.")

        return inst

    @property
    @abstractmethod
    def is_running(self) -> bool:
        pass

    async def start(self) -> None:
        try:
            await self._start()
        except Exception as e:
            self.last_exception = e
            raise
        else:
            self.last_exception = None
        if self.listen_addrs:
            addrs = " and ".join({human.format_address(a) for a in self.listen_addrs})
            logger.info(f"{self.mode.description} listening at {addrs}.")
        else:
            logger.info(f"{self.mode.description} started.")

    async def stop(self) -> None:
        listen_addrs = self.listen_addrs
        try:
            await self._stop()
        except Exception as e:
            self.last_exception = e
            raise
        else:
            self.last_exception = None
        if listen_addrs:
            addrs = " and ".join({human.format_address(a) for a in listen_addrs})
            logger.info(f"{self.mode.description} at {addrs} stopped.")
        else:
            logger.info(f"{self.mode.description} stopped.")

    @abstractmethod
    async def _start(self) -> None:
        pass

    @abstractmethod
    async def _stop(self) -> None:
        pass

    @property
    @abstractmethod
    def listen_addrs(self) -> tuple[Address, ...]:
        pass

    @abstractmethod
    def make_top_layer(self, context: Context) -> Layer:
        pass

    def to_json(self) -> dict:
        return {
            "type": self.mode.type_name,
            "description": self.mode.description,
            "full_spec": self.mode.full_spec,
            "is_running": self.is_running,
            "last_exception": str(self.last_exception) if self.last_exception else None,
            "listen_addrs": self.listen_addrs,
        }

    async def handle_tcp_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        handler = ProxyConnectionHandler(
            ctx.master, reader, writer, ctx.options, self.mode
        )
        handler.layer = self.make_top_layer(handler.layer.context)
        if isinstance(self.mode, mode_specs.TransparentMode):
            s = cast(socket.socket, writer.get_extra_info("socket"))
            try:
                assert platform.original_addr
                original_dst = platform.original_addr(s)
            except Exception as e:
                logger.error(f"Transparent mode failure: {e!r}")
                writer.close()
                return
            else:
                handler.layer.context.client.sockname = original_dst
                handler.layer.context.server.address = original_dst

        with self.manager.register_connection(handler.layer.context.client.id, handler):
            await handler.handle_client()

    def handle_udp_datagram(
        self,
        transport: asyncio.DatagramTransport,
        data: bytes,
        remote_addr: Address,
        local_addr: Address,
    ) -> None:
        # temporary workaround: we don't have a client uuid here.
        connection_id = (remote_addr, local_addr)
        if connection_id not in self.manager.connections:
            reader = udp.DatagramReader()
            writer = udp.DatagramWriter(transport, remote_addr, reader)
            handler = ProxyConnectionHandler(
                ctx.master, reader, writer, ctx.options, self.mode
            )
            handler.timeout_watchdog.CONNECTION_TIMEOUT = 20
            handler.layer = self.make_top_layer(handler.layer.context)
            handler.layer.context.client.transport_protocol = "udp"
            handler.layer.context.server.transport_protocol = "udp"

            # pre-register here - we may get datagrams before the task is executed.
            self.manager.connections[connection_id] = handler
            t = asyncio.create_task(self.handle_udp_connection(connection_id, handler))
            # assign it somewhere so that it does not get garbage-collected.
            handler._handle_udp_task = t  # type: ignore
        else:
            handler = self.manager.connections[connection_id]
            reader = cast(udp.DatagramReader, handler.transports[handler.client].reader)
        reader.feed_data(data, remote_addr)

    async def handle_udp_connection(
        self, connection_id: tuple, handler: ProxyConnectionHandler
    ) -> None:
        with self.manager.register_connection(connection_id, handler):
            await handler.handle_client()


class AsyncioServerInstance(ServerInstance[M], metaclass=ABCMeta):
    _servers: list[asyncio.Server | udp.UdpServer]

    def __init__(self, *args, **kwargs) -> None:
        self._servers = []
        super().__init__(*args, **kwargs)

    @property
    def is_running(self) -> bool:
        return bool(self._servers)

    @property
    def listen_addrs(self) -> tuple[Address, ...]:
        return tuple(
            sock.getsockname() for serv in self._servers for sock in serv.sockets
        )

    async def _start(self) -> None:
        assert not self._servers
        host = self.mode.listen_host(ctx.options.listen_host)
        port = self.mode.listen_port(ctx.options.listen_port)
        try:
            self._servers = await self.listen(host, port)
        except OSError as e:
            message = f"{self.mode.description} failed to listen on {host or '*'}:{port} with {e}"
            if e.errno == errno.EADDRINUSE and self.mode.custom_listen_port is None:
                assert (
                    self.mode.custom_listen_host is None
                )  # since [@ [listen_addr:]listen_port]
                message += f"\nTry specifying a different port by using `--mode {self.mode.full_spec}@{port + 2}`."
            raise OSError(e.errno, message, e.filename) from e

    async def _stop(self) -> None:
        assert self._servers
        try:
            for s in self._servers:
                s.close()
            # https://github.com/python/cpython/issues/104344
            # await asyncio.gather(*[s.wait_closed() for s in self._servers])
        finally:
            # we always reset _server and ignore failures
            self._servers = []

    async def listen(
        self, host: str, port: int
    ) -> list[asyncio.Server | udp.UdpServer]:
        if self.mode.transport_protocol == "tcp":
            # workaround for https://github.com/python/cpython/issues/89856:
            # We want both IPv4 and IPv6 sockets to bind to the same port.
            # This may fail (https://github.com/mitmproxy/mitmproxy/pull/5542#issuecomment-1222803291),
            # so we try to cover the 99% case and then give up and fall back to what asyncio does.
            if port == 0:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(("", 0))
                    fixed_port = s.getsockname()[1]
                    s.close()
                    return [
                        await asyncio.start_server(
                            self.handle_tcp_connection, host, fixed_port
                        )
                    ]
                except Exception as e:
                    logger.debug(
                        f"Failed to listen on a single port ({e!r}), falling back to default behavior."
                    )
            return [await asyncio.start_server(self.handle_tcp_connection, host, port)]
        elif self.mode.transport_protocol == "udp":
            # create_datagram_endpoint only creates one (non-dual-stack) socket, so we spawn two servers instead.
            if not host:
                ipv4 = await udp.start_server(
                    self.handle_udp_datagram,
                    "0.0.0.0",
                    port,
                )
                try:
                    ipv6 = await udp.start_server(
                        self.handle_udp_datagram,
                        "::",
                        port or ipv4.sockets[0].getsockname()[1],
                    )
                except Exception:  # pragma: no cover
                    logger.debug("Failed to listen on '::', listening on IPv4 only.")
                    return [ipv4]
                else:  # pragma: no cover
                    return [ipv4, ipv6]
            return [
                await udp.start_server(
                    self.handle_udp_datagram,
                    host,
                    port,
                )
            ]
        else:
            raise AssertionError(self.mode.transport_protocol)

class RegularInstance(AsyncioServerInstance[mode_specs.RegularMode]):
    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.HttpProxy(context)


class UpstreamInstance(AsyncioServerInstance[mode_specs.UpstreamMode]):
    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.HttpUpstreamProxy(context)


class TransparentInstance(AsyncioServerInstance[mode_specs.TransparentMode]):
    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.TransparentProxy(context)


class ReverseInstance(AsyncioServerInstance[mode_specs.ReverseMode]):
    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.ReverseProxy(context)


class Socks5Instance(AsyncioServerInstance[mode_specs.Socks5Mode]):
    def make_top_layer(self, context: Context) -> Layer:
        return layers.modes.Socks5Proxy(context)


class DnsInstance(AsyncioServerInstance[mode_specs.DnsMode]):
    def make_top_layer(self, context: Context) -> Layer:
        return layers.DNSLayer(context)


# class Http3Instance(AsyncioServerInstance[mode_specs.Http3Mode]):
#     def make_top_layer(self, context: Context) -> Layer:
#         return layers.modes.HttpProxy(context)
