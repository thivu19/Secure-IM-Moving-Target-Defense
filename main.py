"""
    File: main.py 
    
    Description: launcher (Section 3 version)

    To run:
    python main.py server
    python main.py client alice

    FOR LATER STAGES: add `attack` and `test` dispatch for Sections 4 and 5.
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
        m(sys.argv[2])
    else:
        usage()


if __name__ == "__main__":
    main()
