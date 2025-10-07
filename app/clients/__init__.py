try:
    # Prefer real stubs if configured in environment, else fall back to mocks
    from .burp_real_stub import BurpClientReal as BurpClient
except Exception:
    from .burp_client import BurpClient  # mock

try:
    from .gempy_real_stub import GeminiClient as RealGeminiClient
    GeminiClient = RealGeminiClient
except Exception:
    from .gemini_client import GeminiClient  # mock

from .nikto_client import NiktoClient

__all__ = [
    'BurpClient',
    'GeminiClient',
    'NiktoClient',
]


