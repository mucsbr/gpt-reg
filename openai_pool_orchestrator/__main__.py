"""
允许通过 python -m openai_pool_orchestrator 启动服务。
"""

import os
import sys
import threading
from typing import Callable

import uvicorn

from . import __version__

GRACEFUL_SHUTDOWN_TIMEOUT = 5
FORCE_EXIT_TIMEOUT = 3


def _request_server_shutdown(
    server: uvicorn.Server,
    notify_shutdown: Callable[[], None],
    *,
    force: bool = False,
    message: str | None = None,
) -> None:
    if message:
        print(f"\n{message}")
    server.should_exit = True
    if force:
        server.force_exit = True
    notify_shutdown()


def _install_windows_ctrl_handler(
    server: uvicorn.Server,
    notify_shutdown: Callable[[], None],
):
    import ctypes

    kernel32 = ctypes.windll.kernel32
    shutting_down = threading.Event()
    shutdown_finished = threading.Event()

    def _force_exit_after_timeout() -> None:
        if shutdown_finished.wait(GRACEFUL_SHUTDOWN_TIMEOUT):
            return
        _request_server_shutdown(
            server,
            notify_shutdown,
            force=True,
            message="正在强制退出...",
        )
        if shutdown_finished.wait(FORCE_EXIT_TIMEOUT):
            return
        os._exit(130)

    def _ctrl_handler(ctrl_type):
        # CTRL_C_EVENT = 0, CTRL_BREAK_EVENT = 1
        if ctrl_type not in (0, 1):
            return False

        if shutting_down.is_set():
            _request_server_shutdown(
                server,
                notify_shutdown,
                force=True,
                message=None if server.force_exit else "正在强制退出...",
            )
            return True

        shutting_down.set()
        _request_server_shutdown(server, notify_shutdown, message="正在退出...")
        threading.Thread(target=_force_exit_after_timeout, daemon=True).start()
        return True

    handler_routine = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)
    handler = handler_routine(_ctrl_handler)
    kernel32.SetConsoleCtrlHandler(handler, True)

    def _cleanup() -> None:
        shutdown_finished.set()
        try:
            kernel32.SetConsoleCtrlHandler(handler, False)
        except Exception:
            pass

    return _cleanup


def main() -> None:
    print("=" * 50)
    print(f"  OpenAI Pool Orchestrator v{__version__}")
    print("  访问: http://localhost:18421")
    print("  按 Ctrl+C 可退出")
    print("=" * 50)

    from .server import app, request_service_shutdown

    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=18421,
        log_level="warning",
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_TIMEOUT,
    )
    server = uvicorn.Server(config)

    cleanup_ctrl_handler = None
    if sys.platform == "win32":
        cleanup_ctrl_handler = _install_windows_ctrl_handler(server, request_service_shutdown)

    try:
        server.run()
    finally:
        if cleanup_ctrl_handler is not None:
            cleanup_ctrl_handler()


if __name__ == "__main__":
    main()
