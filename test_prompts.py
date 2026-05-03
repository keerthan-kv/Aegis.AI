import sys
sys.path.append('.')

from firewall.scanner import scan
from firewall.policy_engine import apply_policy

with open('ADVERSARIAL_PROMPTS copy.html', 'r', encoding='utf-8') as f:
    content = f.read()

from html.parser import HTMLParser

class PromptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.prompts = []

    def handle_starttag(self, tag, attrs):
        if tag == 'div':
            for attr in attrs:
                if attr[0] == 'data-prompt-text':
                    self.prompts.append(attr[1])

parser = PromptParser()
parser.feed(content)

failed = []
for prompt in parser.prompts:
    detections = scan(prompt)
    res = apply_policy("ADMIN", detections)
    if res["action"] != "BLOCK":
        failed.append(prompt)

print(f"Total failed: {len(failed)}")
import random
for p in failed[:5]:
    print(repr(p))
