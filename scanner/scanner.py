import os
import sys
import subprocess
import time

from rules import check_file
from ai.llm_explainer import explain_vulnerability

vulnerabilities_found = False


def clone_repo(repo_url):
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    os.makedirs("temp_repos", exist_ok=True)

    clone_path = f"temp_repos/{repo_name}_{os.getpid()}"

    print(f"🌐 Cloning repository into {clone_path}...\n")
    subprocess.run(["git", "clone", repo_url, clone_path], check=True)

    return clone_path


def safe_explain(issue, line, path):
    try:
        return explain_vulnerability(issue, line, path)
    except Exception:
        return "⚠ AI skipped (slow or not responding)"


def run_scan(scan_path):
    global vulnerabilities_found

    print("🔍 Starting Security Scan...\n")

    for root, dirs, files in os.walk(scan_path):

        if ".git" in root:
            continue

        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)

                try:
                    issues = check_file(path)

                    for issue, line_no, line in issues:
                        print(f"[!] {issue} detected in {path} at line {line_no}")
                        print(f"👉 Code: {line}\n")

                        print("⏳ Trying AI explanation...(max 10s)\n")

                        start = time.time()

                        explanation = safe_explain(issue, line, path)

                        # ⛔ If too slow → skip
                        if time.time() - start > 30:
                            explanation = "⚠ AI skipped (too slow)"

                        print("🤖 AI Security Analysis:\n")
                        print(explanation)
                        print("-" * 60)

                        vulnerabilities_found = True

                except Exception as e:
                    print(f"⚠ Could not read file {path}: {e}")


if __name__ == "__main__":

    if len(sys.argv) == 2:
        repo_url = sys.argv[1]
        repo_path = clone_repo(repo_url)
    else:
        print("🔄 Running in CI mode (Scanning current repository)\n")
        repo_path = "."

    run_scan(repo_path)

    if vulnerabilities_found:
        print("\n❌ Vulnerabilities Found! Failing the pipeline.")
        sys.exit(1)
    else:
        print("\n✅ No vulnerabilities found.")
        sys.exit(0)