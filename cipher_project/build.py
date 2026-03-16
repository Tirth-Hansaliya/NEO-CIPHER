import os
import re

def build():
    src_dir = os.path.join(os.path.dirname(__file__), 'src')
    output_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cipher-calculator.html')
    
    with open(os.path.join(src_dir, 'index.html'), 'r', encoding='utf-8') as f:
        html_content = f.read()

    # Find and inline CSS
    css_pattern = re.compile(r'<link rel="stylesheet" href="(.*?)">')
    def css_replacer(match):
        css_path = os.path.join(src_dir, match.group(1))
        with open(css_path, 'r', encoding='utf-8') as cf:
            css_data = cf.read()
        return f'<style>\n{css_data}\n</style>'
    
    html_content = css_pattern.sub(css_replacer, html_content)

    # Find and inline JS
    js_pattern = re.compile(r'<script src="(.*?)"></script>')
    def js_replacer(match):
        js_path = os.path.join(src_dir, match.group(1))
        with open(js_path, 'r', encoding='utf-8') as jf:
            js_data = jf.read()
        return f'<script>\n{js_data}\n</script>'
    
    html_content = js_pattern.sub(js_replacer, html_content)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"Built {output_file} successfully.")

if __name__ == '__main__':
    build()
