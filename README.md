# Secure-IM-Moving-Target-Defense
Implement a small Instant Messaging (IM) system in which users can find one another, establish private chat sessions, and communicate directly

--- 

## Requirements

- Python 3.11 or newer
- Dependencies listed in `requirements.txt`

--- 

## Setup

1. Create and activate a virtual environment:

```bash
   python -m venv .venv

   # In Mac:
   source .venv/bin/activate     

   # In Windows: 
   .venv\Scripts\activate
```

2. Install dependencies:

```bash
   pip install -r requirements.txt
```

--- 

**Note:** 
- This current version is for Section 3: Functional IM Application. 
- To be added later in next stages: Section 4: Security of the IM Application and Section 5: Moving-Target Defense

## Running

Open separate terminals for the server and each client.

```bash
python main.py server          # Terminal 1
python main.py client alice    # Terminal 2
python main.py client bob      # Terminal 3
```

--- 

## Usage

Once logged in, each client accepts these commands:

| Command           | Action                             |
|-------------------|------------------------------------|
| `/list`           | Show available users               |
| `/chat <user>`    | Request a chat with a user         |
| `/accept <user>`  | Accept an incoming invitation      |
| `/decline <user>` | Decline an incoming invitation     |
| `/msg <text>`     | Send a message in the current chat |
| `/end`            | End the current chat               |
| `/quit`           | Log out and exit                   |
| `/help`           | List commands                      |

**Example:**

1. In **alice**: `/list`, then `/chat bob`
2. In **bob**: `/accept alice`
3. Either side: `/msg hello`
4. Either side: `/end`, then `/quit`

The server coordinates the chat setup, but messages are sent **directly**
between the two clients — the server never relays chat content.

--- 
