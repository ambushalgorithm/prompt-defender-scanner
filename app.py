"""Prompt Defender Security Service."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Optional
import time
import json

from logger import get_logger
from scanner import get_scanner
from decoder import decode_and_scan, has_encoding
from config import load_config, ServiceConfig

app = FastAPI(title="Prompt Defender Security Service")
logger = get_logger()
scanner = get_scanner()

# Allow CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    """Simplified scan request - just content and optional config."""
    content: Any
    features: Optional[dict] = None
    scan_tier: Optional[int] = None


class ScanResponse(BaseModel):
    action: str  # "allow", "block", "sanitize"
    reason: Optional[str] = None
    sanitized_content: Optional[Any] = None
    matches: Optional[list[dict]] = None


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    """Scan content for prompt injection attempts."""
    start_time = time.time()
    
    # Build config from flattened request
    config_dict = {}
    if request.features:
        config_dict["features"] = request.features
    if request.scan_tier is not None:
        if "prompt_guard" not in config_dict:
            config_dict["prompt_guard"] = {}
        config_dict["prompt_guard"]["scan_tier"] = request.scan_tier
    
    # Load configuration
    try:
        config = load_config(config_dict)
    except (json.JSONDecodeError, ValueError):
        config = ServiceConfig()
    
    # Convert content to string for scanning
    content_str = str(request.content)
    
    # Check if prompt_guard feature is enabled
    if not config.features.prompt_guard:
        return ScanResponse(action="allow", reason="prompt_guard disabled")
    
    # Decode any encoded content if enabled
    decoded_findings = []
    if config.prompt_guard.decode_base64 and has_encoding(content_str):
        decoded_findings = decode_and_scan(content_str)
        
        # Scan decoded content too
        for finding in decoded_findings:
            content_str += "\n" + finding["decoded"]
    
    # Scan content with tiered scanner
    is_dangerous, matches, scan_duration_ms = scanner.scan(
        content=content_str,
        tier=config.prompt_guard.scan_tier,
        use_cache=config.prompt_guard.hash_cache
    )
    
    total_duration_ms = int((time.time() - start_time) * 1000)
    
    if is_dangerous:
        severity = "critical" if any(m["severity"] == "critical" for m in matches) else "high"
        
        # Log the match
        print(f"[PROMPT DEFENDER] Blocked: {len(matches)} match(es)")
        for m in matches:
            print(f"  - {m['type']}: {m['pattern'][:30]}...")
        
        if decoded_findings:
            print(f"  - Decoded {len(decoded_findings)} encoded string(s)")
        
        # Log threat to persistent storage
        logger.log_threat(
            severity=severity,
            tool_name="unknown",  # Removed from API
            matches=matches,
            content=request.content,
            source=None  # Removed from API
        )
        
        # Log scan event
        logger.log_scan(
            action="block",
            tool_name="unknown",
            severity=severity,
            matches=matches,
            duration_ms=total_duration_ms,
            source=None
        )
        
        return ScanResponse(
            action="block",
            reason=f"Potential prompt injection detected ({len(matches)} pattern(s) matched)",
            matches=matches
        )
    
    # Log allowed scan
    logger.log_scan(
        action="allow",
        tool_name="unknown",
        severity="safe",
        matches=[],
        duration_ms=total_duration_ms,
        source=None
    )
    
    # Allow through
    return ScanResponse(action="allow")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "prompt-defender",
        "version": "0.2.0",
        "scanner": scanner.get_stats()
    }


@app.get("/stats")
async def get_stats(hours: int = 24):
    """Get threat statistics for the last N hours."""
    stats = logger.get_stats(hours=hours)
    stats["scanner"] = scanner.get_stats()
    return stats


@app.get("/patterns")
async def list_patterns():
    """List active detection patterns."""
    scanner_stats = scanner.get_stats()
    return {
        "patterns_loaded": scanner_stats["patterns_loaded"],
        "cache_stats": {
            "size": scanner_stats["cache_size"],
            "hits": scanner_stats["cache_hits"],
            "misses": scanner_stats["cache_misses"],
            "hit_rate": scanner_stats["hit_rate_percent"]
        }
    }


@app.post("/cache/clear")
async def clear_cache():
    """Clear the pattern cache."""
    scanner.clear_cache()
    return {"status": "cleared", "message": "Pattern cache cleared"}


if __name__ == "__main__":
    import uvicorn
    print("Starting Prompt Defender service on http://0.0.0.0:8080")
    print("Endpoints:")
    print("  POST /scan        - Scan tool result for prompt injection")
    print("  GET  /health      - Health check + scanner stats")
    print("  GET  /stats       - Threat statistics")
    print("  GET  /patterns    - List active patterns")
    print("  POST /cache/clear - Clear pattern cache")
    uvicorn.run(app, host="0.0.0.0", port=8080)
