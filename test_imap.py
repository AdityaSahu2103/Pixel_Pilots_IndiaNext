import imaplib
import sys

email_addr = sys.argv[1]
app_pwd = sys.argv[2]
clean_pwd = app_pwd.replace(" ", "")

try:
    print(f"Connecting to imap.gmail.com for {email_addr}...")
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(email_addr, clean_pwd)
    print("Login successful!")
    
    mail.select("inbox")
    print("Selected inbox")
    
    print("Trying search: 'UNREAD'")
    try:
        status, messages = mail.search(None, "UNREAD")
        print(f"Result 1: {status}, {messages}")
    except Exception as e:
        print(f"Search 1 failed: {e}")
        
    print("Trying search: '(UNREAD)'")
    try:
        status, messages = mail.search(None, '(UNREAD)')
        print(f"Result 2: {status}, {messages}")
    except Exception as e:
        print(f"Search 2 failed: {e}")
        
    print("Trying search: 'ALL'")
    try:
        status, messages = mail.search(None, 'ALL')
        print(f"Result 3: {status}, {messages}")
    except Exception as e:
        print(f"Search 3 failed: {e}")

    mail.logout()
    print("Logged out successfully.")
except Exception as e:
    print(f"Error: {e}")
