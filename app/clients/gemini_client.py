class GeminiClient:
    def __init__(self):
        pass
    def chat(self, prompt, max_output_tokens=512):
        return '{"summary":"Mocked response","payloads":["<script>alert(1)</script>"],"verification":["Non-Destructive"],"remediation":"Use encoding & parameterized queries."}'
