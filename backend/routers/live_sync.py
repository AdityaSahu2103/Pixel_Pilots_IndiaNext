"""
CyberShield AI - Live Data Sync Router
Endpoints for connecting live data sources (like IMAP email).
"""
import imaplib
import email
from email.policy import default
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from backend.models.schemas import ScanRequest, SourceType, ScanResponse
from backend.agents.orchestrator import OrchestratorAgent

router = APIRouter(prefix="/api/live", tags=["Live Integrations"])

# Singleton orchestrator
orchestrator = OrchestratorAgent()


class ImapCredentials(BaseModel):
    email_address: str = Field(..., description="Gmail or IMAP email address")
    app_password: str = Field(..., description="16-character IMAP App Password (not your regular password)")
    imap_server: str = Field(default="imap.gmail.com", description="IMAP server hostname")
    limit: int = Field(default=5, ge=1, le=20, description="Number of recent unread emails to fetch")


@router.post("/sync/email", response_model=list[dict])
async def sync_live_email(creds: ImapCredentials):
    """
    Connects to an IMAP mailbox, fetches recent unread emails,
    and automatically scans them using the AI pipeline.
    """
    try:
        # 1. Connect and login via IMAP
        mail = imaplib.IMAP4_SSL(creds.imap_server)
        
        # Google provides app passwords with spaces often (e.g. 'abcd efgh ijkl mnop')
        # We must strip them for IMAP login to work.
        clean_password = creds.app_password.replace(" ", "")
        
        mail.login(creds.email_address, clean_password)
        # Select INBOX explicitly
        status, messages = mail.select("INBOX")
        print(f"IMAP Select INBOX returned: format={status}, messages={messages}")
        if status != "OK":
            mail.logout()
            raise HTTPException(status_code=500, detail=f"Failed to select INBOX. Server responded: {status} {messages}")

        # 2. Search for UNSEEN emails
        print(f"Executing search command for UNSEEN...")
        try:
            status, messages = mail.search(None, "UNSEEN")
            print(f"IMAP Search returned: {status}, {messages}")
        except Exception as search_err:
            print(f"IMAP Search failed entirely! Error: {search_err}")
            raise

        if status != "OK":
            mail.logout()
            raise HTTPException(status_code=500, detail="Failed to search INBOX.")

        # 3. Get the latest N email IDs
        email_ids = messages[0].split()
        if not email_ids:
            mail.logout()
            return []  # No unread emails

        # Take the last N (most recent)
        recent_ids = email_ids[-creds.limit:]
        
        results = []
        for e_id in reversed(recent_ids):
            # Fetch raw email
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            if res != "OK":
                continue

            # Parse email bytes into string suitable for our pipeline
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    raw_email_bytes = response_part[1]
                    # Parse to get subject/sender for quick reference in API response
                    msg = email.message_from_bytes(raw_email_bytes, policy=default)
                    subject = str(msg.get("Subject", "No Subject"))
                    sender = str(msg.get("From", "Unknown Sender"))
                    
                    # Convert raw bytes to standard string format for our pipeline
                    raw_email_str = raw_email_bytes.decode("utf-8", errors="replace")

                    # 4. Run through CyberShield AI Pipeline
                    scan_request = ScanRequest(
                        source_type=SourceType.EMAIL,
                        content=raw_email_str,
                        metadata={
                            "sender": sender,
                            "subject": subject,
                            "live_sync": True
                        }
                    )
                    
                    try:
                        print(f"Submitting email to orchestrator: {subject}")
                        scan_result = await orchestrator.scan(scan_request)
                        print(f"Scan complete for {subject}")
                        
                        # Add to summary results
                        results.append({
                            "subject": subject,
                            "sender": sender,
                            "risk_score": scan_result.risk_score.overall_score,
                            "severity": scan_result.risk_score.severity.value,
                            "threats": [d.threat_type.value for d in scan_result.detections if d.detected],
                            "scan_id": scan_result.scan_id
                        })
                        
                        # Store in global state so frontend can fetch full details later
                        from backend.routers.reports import store_scan
                        store_scan(scan_result)
                        
                    except Exception as e:
                        import traceback
                        print(f"FAILED ON EMAIL {subject}!")
                        print(traceback.format_exc())
                        raise e  # Force the exception up so we can see it in Uvicorn

        # 5. Logout safely
        mail.logout()
        return results

    except imaplib.IMAP4.error as e:
        print(f"IMAP Auth Error: {e}")
        raise HTTPException(
            status_code=401, 
            detail=f"Authentication failed. Are you sure it's an App Password? Error: {str(e)}"
        )
    except Exception as e:
        print(f"IMAP Generic Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
