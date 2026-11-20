"""
    File: main.py
    
    Description: Launcher.
        python main.py server
        python main.py client <user>
"""
import sys


def usage():
    print("usage:")
    print("  python main.py server")
    print("  python main.py client <user>")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        usage()
    role = sys.argv[1]
    if role == "server":
        from server.server import main as m
        m()
    elif role == "client" and len(sys.argv) >= 3:
        from client.client import main as m
        # optional: "--key <other>" signs with another user's key (impersonation demo)
        key_user = None
        if "--key" in sys.argv:
            i = sys.argv.index("--key")
            if i + 1 < len(sys.argv):
                key_user = sys.argv[i + 1]
        m(sys.argv[2], key_user)
    else:
        usage()


if __name__ == "__main__":
    main()
