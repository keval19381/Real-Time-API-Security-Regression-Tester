import os
import sys
import time
import subprocess
import uvicorn
import httpx

def wait_for_service(url: str, timeout: int = 15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = httpx.get(url, timeout=1.0)
            if r.status_code == 200:
                print(f"[+] Service ready at {url}")
                return True
        except Exception:
            pass
        time.sleep(0.5)
    print(f"[-] Service at {url} did not become ready in {timeout}s")
    return False

def main():
    target_port = 8001
    backend_port = int(os.environ.get("PORT", 8000))

    print(f"[*] Starting Target App (mock vulnerable B2B service) on port {target_port}...")
    target_process = subprocess.Popen([
        sys.executable, "-m", "uvicorn", "target_app.app:app",
        "--host", "127.0.0.1",
        "--port", str(target_port)
    ])

    # Wait for target app to be healthy
    wait_for_service(f"http://127.0.0.1:{target_port}/health")

    print(f"[*] Starting DAST Backend & Live Dashboard on 0.0.0.0:{backend_port}...")
    try:
        uvicorn.run(
            "backend.app:app",
            host="0.0.0.0",
            port=backend_port,
            log_level="info"
        )
    finally:
        print("[*] Shutting down Target App process...")
        target_process.terminate()
        target_process.wait()

if __name__ == "__main__":
    main()
