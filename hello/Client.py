import httpx
import asyncio

async def make_request():
    url = "https://127.0.0.1:8443"
    async with httpx.AsyncClient(http2=True, verify="cert.pem") as client:
        for i in range(101):  # Increased number of requests
            payload = {"message": f"Hello from client {i}"}
            response = await client.post(url, json=payload)
            print(f"Request {i}: {payload}")
            print(f"Response {i}: {response.json()}")
            await asyncio.sleep(0.5)  # Shorter interval for more traffic

if __name__ == "__main__":
    asyncio.run(make_request())
