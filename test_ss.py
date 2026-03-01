import asyncio
import sys
from screenshot import take_screenshot, init_screenshot_dir

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

async def main():
    print("Initializing...")
    await init_screenshot_dir()
    print("Taking screenshot...")
    res = await take_screenshot("http://93.184.216.34", "93.184.216.34", 80)
    print("Result:", res)

if __name__ == "__main__":
    asyncio.run(main())
