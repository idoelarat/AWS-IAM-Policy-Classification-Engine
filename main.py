import os
import json
import time
import argparse
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(api_key=os.getenv("Api_key"))

MODEL_ID = "gpt-4o"

CLASSIFICATION_CRITERIA = {
    "AWS": "Analyze AWS IAM: WEAK if has Action: '*', Resource: '*', or iam:PassRole without constraints.",
    "GCP": "Analyze GCP IAM: WEAK if using Primitive Roles (Owner, Editor) instead of Predefined/Custom roles, or broad member access (allUsers).",
    "AZURE": "Analyze Azure RBAC: WEAK if 'assignableScopes' is '/' (root) with high-privilege actions or wildcard '*' in actions.",
}


def detect_cloud_provider(policy_json: dict) -> str:
    policy_str = json.dumps(policy_json)
    if "Statement" in policy_json or "Version" in policy_json:
        return "AWS"
    if "bindings" in policy_json or "role" in policy_str:
        return "GCP"
    if "assignableScopes" in policy_json or "properties" in policy_json:
        return "AZURE"
    return "AWS"


class IAMAgenticSystem:
    def __init__(self):
        self.criteria_map = CLASSIFICATION_CRITERIA

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = client.chat.completions.create(
                model=MODEL_ID,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            print(f"[!] OpenAI Error: {e}")
            raise e

    def analyze_policy(self, policy_json: dict):
        provider = detect_cloud_provider(policy_json)
        criteria = self.criteria_map.get(provider)

        system_msg = (
            f"You are a Senior Cloud Security Researcher. Target Provider: {provider}.\n"
            f"Criteria: {criteria}\n"
            "Return ONLY a JSON with 'classification' (WEAK/STRONG), 'provider', and 'reason'."
        )
        user_msg = f"Policy: {json.dumps(policy_json)}"
        content = self._call_llm(system_msg, user_msg)
        return json.loads(content)

    def remediate_policy(self, policy_json: dict, reason: str):
        provider = detect_cloud_provider(policy_json)
        system_msg = (
            f"You are a Senior {provider} Security Engineer. Fix the WEAK policy to follow Least Privilege. "
            "Return ONLY JSON with 'fixed_policy' and 'explanation'."
        )
        user_msg = f"Reason: {reason}\nOriginal Policy: {json.dumps(policy_json)}"
        content = self._call_llm(system_msg, user_msg)
        return json.loads(content)


def validate_json(data) -> bool:
    try:
        if isinstance(data, str):
            json.loads(data)
        return True
    except:
        return False


def run_system(input_policy: dict):
    agent = IAMAgenticSystem()
    print("[*] Starting Agentic Analysis (OpenAI)...")
    analysis = agent.analyze_policy(input_policy)

    result = {"original_policy": input_policy, "analysis": analysis}

    if analysis.get("classification") == "WEAK":
        print(f"[!] Verdict: WEAK. Reason: {analysis.get('reason')}")

        max_retries = 3
        attempt = 0
        while attempt < max_retries:
            remediation = agent.remediate_policy(
                input_policy, analysis.get("reason", "")
            )

            if validate_json(remediation.get("fixed_policy")):
                result["remediation"] = remediation
                print(
                    f"[+] Remediation complete and validated (Attempt {attempt + 1})."
                )
                break
            else:
                attempt += 1
                print(f"[?] Invalid JSON format, retrying... ({attempt}/{max_retries})")

        if attempt == max_retries:
            print(
                "[X] Failed to generate a valid JSON remediation after multiple attempts."
            )

    else:
        print("[+] Verdict: STRONG. No changes required.")

    return result


def process_file(file_path):
    try:
        with open(file_path, "r") as f:
            policy = json.load(f)
        result = run_system(policy)
        print("\n--- FINAL AGENT REPORT ---")
        print(json.dumps(result, indent=4))
        return result
    except Exception as e:
        print(f"[X] Error processing file {file_path}: {e}")


def process_directory(directory_path):
    full_results = []
    if not os.path.exists(directory_path):
        print(f"[X] Directory {directory_path} not found.")
        return

    files = [f for f in os.listdir(directory_path) if f.endswith(".json")]
    print(f"[*] Processing {len(files)} files in '{directory_path}'...")

    for filename in files:
        file_path = os.path.join(directory_path, filename)
        print(f"\n>>> ANALYZING FILE: {filename}")

        start_time = time.time()
        policy = load_policy(file_path)
        result = run_system(policy)

        print(f"--- Result for {filename} ---")
        print(json.dumps(result["analysis"], indent=2))
        if "remediation" in result:
            print(f"[V] Fixed Policy generated for {filename}")

        result["metadata"] = {
            "filename": filename,
            "processing_time_sec": round(time.time() - start_time, 2),
        }
        full_results.append(result)

    output_filename = "final_evaluation_report.json"
    with open(output_filename, "w") as out_f:
        json.dump(full_results, out_f, indent=4)
    print(f"\n[V] Batch processing complete. Results saved to {output_filename}")


def load_policy(path):
    with open(path, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AWS IAM Policy Agentic Classification Engine"
    )
    parser.add_argument("--file", type=str, help="Path to a single JSON policy file")
    parser.add_argument(
        "--dir", type=str, help="Path to a directory containing multiple JSON policies"
    )

    args = parser.parse_args()

    if args.file:
        process_file(args.file)
    elif args.dir:
        process_directory(args.dir)
    else:
        test_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
        final = run_system(test_policy)
        print(json.dumps(final, indent=4))
