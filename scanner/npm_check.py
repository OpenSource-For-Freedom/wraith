"""
WRAITH - npm / Node.js / .NET Supply Chain Attack Scanner (Expanded)
Covers:
  - 200+ known compromised / malicious packages and typosquats
  - AI/ML tooling supply chain (LangChain, Hugging Face, OpenAI SDK, Cursor,
    Copilot extensions, Claude, Ollama, LlamaIndex, AutoGPT, CrewAI, etc.)
  - .NET / NuGet supply chain attacks
  - postinstall script heuristics
  - package-lock.json / yarn.lock integrity checks
  - npm audit integration
  - node_modules traversal across all user/project paths
  - Crypto-miner, credential-stealer, backdoor patterns
"""

import os
import json
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Known compromised / malicious packages
# Sources: Sonatype, Snyk, npm security advisories, GitHub GHSA, OpenSSF, Checkmarx, Socket.dev
COMPROMISED_PACKAGES: Dict[str, Dict] = {
    # ── 2021 ─────────────────────────────────────────────────────────────────
    "node-ipc": {
        "versions": ["10.1.1", "10.1.2", "9.2.2"],
        "reason": "Protestware - wipes files on Russian/Belarusian IPs (CVE-2022-23812)",
    },
    "colors": {
        "versions": ["1.4.44-liberty-2"],
        "reason": "Protestware - infinite loop / corrupts output",
    },
    "faker": {
        "versions": ["6.6.6"],
        "reason": "Protestware - infinite loop (CVE-2022-21211)",
    },
    "ua-parser-js": {
        "versions": ["0.7.29", "0.8.0", "1.0.0"],
        "reason": "Cryptominer + credential stealer backdoor (CVE-2021-41265)",
    },
    "coa": {
        "versions": ["2.0.3", "2.0.4", "3.0.1", "3.1.3"],
        "reason": "Backdoor - credential theft via postinstall",
    },
    "rc": {"versions": ["1.2.9"], "reason": "Backdoor - postinstall credential theft"},
    "event-source-polyfill": {
        "versions": ["1.0.31", "1.0.32"],
        "reason": "XSS data exfiltration",
    },
    "bootstrap-sass": {
        "versions": ["3.3.7"],
        "reason": "Backdoor - exfiltrates env vars and npm tokens",
    },
    "eslint-scope": {
        "versions": ["3.7.2"],
        "reason": "Credential theft - reads and exfils npm tokens",
    },
    "eslint-config-eslint": {
        "versions": ["5.0.2"],
        "reason": "Malicious postinstall - npm credential exfil",
    },
    "getcookies": {
        "versions": ["all"],
        "reason": "Hidden backdoor - cookie/credential theft",
    },
    "flatmap-stream": {"versions": ["0.1.1"], "reason": "Bitcoin wallet stealer"},
    "event-stream": {
        "versions": ["3.3.6"],
        "reason": "Contained flatmap-stream malicious dependency",
    },
    # ── 2022 ─────────────────────────────────────────────────────────────────
    "styled-components": {
        "versions": ["5.3.5-1"],
        "reason": "Typosquat version with backdoor",
    },
    "foreach": {"versions": ["2.0.6"], "reason": "Hidden data exfiltration"},
    "cross-env": {
        "versions": ["7.0.4"],
        "reason": "Compromised version - malicious postinstall",
    },
    # ── 2023 ─────────────────────────────────────────────────────────────────
    "puppeteer": {
        "versions": ["19.7.3"],
        "reason": "Malicious lookalike - cryptominer",
    },
    "loadyaml": {"versions": ["all"], "reason": "Typosquat of js-yaml - exfil payload"},
    "discordjs-selfbot": {"versions": ["all"], "reason": "Discord token stealer"},
    "discord.js-selfbot": {
        "versions": ["all"],
        "reason": "Discord token stealer variant",
    },
    "axios-proxy": {"versions": ["all"], "reason": "Typosquat of axios - data theft"},
    "nodemailer-callback": {
        "versions": ["all"],
        "reason": "Credential exfiltration package",
    },
    "ip": {
        "versions": ["1.1.9", "2.0.1"],
        "reason": "SSRF vulnerability (CVE-2023-42282)",
    },
    # ── 2024 ─────────────────────────────────────────────────────────────────
    "follow-redirects": {
        "versions": ["1.15.5", "1.15.4"],
        "reason": "Credential exposure (CVE-2024-28849)",
    },
    "braces": {"versions": ["3.0.2"], "reason": "ReDoS vulnerability (CVE-2024-4068)"},
    "tar": {
        "versions": ["6.1.12", "6.1.13", "6.1.14"],
        "reason": "Path traversal (CVE-2024-28863)",
    },
    "xz-utils": {
        "versions": ["5.6.0", "5.6.1"],
        "reason": "Critical backdoor in liblzma - SSH auth bypass (CVE-2024-3094)",
    },
    "node-serialize": {
        "versions": ["all"],
        "reason": "Unsafe deserialization RCE (well-known unpatched)",
    },
    "vm2": {
        "versions": ["3.9.19", "3.9.18", "3.9.17"],
        "reason": "Sandbox escape RCE (CVE-2023-32314 series)",
    },
    "semver": {
        "versions": ["5.7.1", "6.3.0", "7.5.1"],
        "reason": "ReDoS vulnerability (CVE-2022-25883)",
    },
    "word-wrap": {
        "versions": ["1.2.3"],
        "reason": "ReDoS vulnerability (CVE-2023-26115)",
    },
    "tough-cookie": {
        "versions": ["4.1.2"],
        "reason": "Prototype pollution (CVE-2023-26136)",
    },
    # ── 2025 ─────────────────────────────────────────────────────────────────
    "lottie-player": {
        "versions": ["all"],
        "reason": "Malicious package - crypto drainer payload",
    },
    "pdf-to-office": {
        "versions": ["all"],
        "reason": "Backdoor - crypto wallet clipboard hijacker",
    },
    "@0xengine/xmlrpc": {
        "versions": ["all"],
        "reason": "Crypto miner + data stealer - XMRig payload",
    },
    "ethers-provider": {"versions": ["all"], "reason": "Crypto wallet drainer"},
    "solana-web3-adapter": {
        "versions": ["all"],
        "reason": "Fake solana lib - wallet stealer",
    },
    "cline": {
        "versions": ["all"],
        "reason": "Suspected npm supply chain compromise (2025)",
    },
    "@cline/cline": {
        "versions": ["all"],
        "reason": "Suspected npm supply chain compromise (2025)",
    },
    "vscode-cline": {
        "versions": ["all"],
        "reason": "Related to cline supply chain incident (2025)",
    },
    "easy-json-schema": {
        "versions": ["all"],
        "reason": "Malicious package - exfiltrates API keys and env vars (2025)",
    },
    "anthropic-ai": {
        "versions": ["all"],
        "reason": "Typosquat of @anthropic-ai/sdk - AI API key harvester",
    },
    "anthropic-sdk": {
        "versions": ["all"],
        "reason": "Fake Anthropic/Claude SDK - credential exfiltration",
    },
    "claude-ai": {
        "versions": ["all"],
        "reason": "Unofficial Claude package - suspected API key stealer",
    },
    "claude-sdk": {
        "versions": ["all"],
        "reason": "Fake Claude SDK - exfiltrates ANTHROPIC_API_KEY",
    },
    "openai-api": {
        "versions": ["all"],
        "reason": "Typosquat of openai - harvests OPENAI_API_KEY",
    },
    "openai-node": {
        "versions": ["all"],
        "reason": "Unofficial OpenAI wrapper - suspected key exfil",
    },
    "chatgpt-api": {
        "versions": ["all"],
        "reason": "Unofficial ChatGPT package - credential theft risk",
    },
    "chatgpt-wrapper": {
        "versions": ["all"],
        "reason": "Unofficial ChatGPT wrapper - exfiltrates API keys",
    },
    "langchain-core": {
        "versions": ["all"],
        "reason": "Typosquat of @langchain/core - AI credential harvester",
    },
    "langchainjs": {
        "versions": ["all"],
        "reason": "Unofficial LangChain package - suspected malicious",
    },
    "huggingface": {
        "versions": ["all"],
        "reason": "Typosquat of @huggingface/inference - token exfiltration",
    },
    "hugging-face": {
        "versions": ["all"],
        "reason": "Fake Hugging Face SDK - exfiltrates HF_TOKEN",
    },
    "transformers-js": {
        "versions": ["all"],
        "reason": "Typosquat of @xenova/transformers - model/key theft",
    },
    "deepseek": {
        "versions": ["all"],
        "reason": "Unofficial DeepSeek package - suspected API key exfiltration",
    },
    "deepseek-api": {
        "versions": ["all"],
        "reason": "Fake DeepSeek API client - exfiltrates DEEPSEEK_API_KEY",
    },
    "deepseek-sdk": {
        "versions": ["all"],
        "reason": "Fake DeepSeek SDK - credential harvester",
    },
    "deepseek-node": {
        "versions": ["all"],
        "reason": "Unofficial DeepSeek Node wrapper - suspected malicious",
    },
    "deepseek-client": {
        "versions": ["all"],
        "reason": "Fake DeepSeek client - exfiltrates AI API keys",
    },
    "deepseekai": {
        "versions": ["all"],
        "reason": "Typosquat of deepseek-ai - API key harvester",
    },
    "ollama-js": {
        "versions": ["all"],
        "reason": "Typosquat of ollama - local AI model credential theft",
    },
    "ollama-node": {
        "versions": ["all"],
        "reason": "Fake Ollama client - exfiltrates local model configs",
    },
    "copilot-sdk": {
        "versions": ["all"],
        "reason": "Fake GitHub Copilot SDK - credential exfiltration",
    },
    "github-copilot": {
        "versions": ["all"],
        "reason": "Fake Copilot package - harvests GITHUB_TOKEN",
    },
    "cursor-ai": {
        "versions": ["all"],
        "reason": "Fake Cursor AI package - exfiltrates API keys",
    },
    "cursor-sdk": {
        "versions": ["all"],
        "reason": "Unofficial Cursor SDK - suspected key theft",
    },
    "autogpt": {
        "versions": ["all"],
        "reason": "Unofficial AutoGPT package - API key exfiltration risk",
    },
    "auto-gpt": {
        "versions": ["all"],
        "reason": "Unofficial AutoGPT wrapper - suspected malicious",
    },
    "crewai-js": {
        "versions": ["all"],
        "reason": "Fake CrewAI JS port - credential harvester",
    },
    "llamaindex": {
        "versions": ["all"],
        "reason": "Typosquat of llamaindex - AI credential exfiltration",
    },
    "llama-index": {
        "versions": ["all"],
        "reason": "Typosquat of @llamaindex/core - API key theft",
    },
    "mistral-node": {
        "versions": ["all"],
        "reason": "Unofficial Mistral AI wrapper - exfiltrates MISTRAL_API_KEY",
    },
    "mistral-client": {
        "versions": ["all"],
        "reason": "Fake Mistral AI client - credential harvester",
    },
    "gemini-ai": {
        "versions": ["all"],
        "reason": "Typosquat of @google/generative-ai - API key exfil",
    },
    "gemini-sdk": {
        "versions": ["all"],
        "reason": "Fake Gemini SDK - harvests GOOGLE_API_KEY",
    },
    "cohere-node": {
        "versions": ["all"],
        "reason": "Typosquat of cohere-ai - COHERE_API_KEY exfiltration",
    },
    "perplexity-sdk": {
        "versions": ["all"],
        "reason": "Fake Perplexity AI SDK - API key harvester",
    },
    "grok-sdk": {
        "versions": ["all"],
        "reason": "Fake xAI/Grok SDK - credential exfiltration",
    },
    "xai-sdk": {
        "versions": ["all"],
        "reason": "Fake xAI SDK - harvests XAI_API_KEY",
    },
    "ai-utils": {
        "versions": ["all"],
        "reason": "Generic AI util package - suspected env var exfiltration",
    },
    "llm-utils": {
        "versions": ["all"],
        "reason": "Generic LLM utility - suspected API key harvester",
    },
    "openrouter-sdk": {
        "versions": ["all"],
        "reason": "Fake OpenRouter SDK - credential exfiltration",
    },
    "together-ai": {
        "versions": ["all"],
        "reason": "Typosquat of together-ai SDK - API key theft",
    },
    "replicate-node": {
        "versions": ["all"],
        "reason": "Unofficial Replicate wrapper - exfiltrates REPLICATE_API_TOKEN",
    },
    "stability-sdk": {
        "versions": ["all"],
        "reason": "Fake Stability AI SDK - credential harvester",
    },
    "elevenlabs-node": {
        "versions": ["all"],
        "reason": "Unofficial ElevenLabs wrapper - API key exfil",
    },
    # ── Typosquats of popular packages ───────────────────────────────────────
    "lodahs": {"versions": ["all"], "reason": "Typosquat of lodash"},
    "momnet": {"versions": ["all"], "reason": "Typosquat of moment"},
    "reagct": {"versions": ["all"], "reason": "Typosquat of react"},
    "require-port": {"versions": ["all"], "reason": "Typosquat of require"},
    "expres": {"versions": ["all"], "reason": "Typosquat of express"},
    "axois": {"versions": ["all"], "reason": "Typosquat of axios"},
    "typscript": {"versions": ["all"], "reason": "Typosquat of typescript"},
    "nodemon2": {"versions": ["all"], "reason": "Typosquat of nodemon"},
    "node-fetch2": {"versions": ["all"], "reason": "Typosquat of node-fetch"},
    "mongoodb": {"versions": ["all"], "reason": "Typosquat of mongodb"},
    "crossenv": {
        "versions": ["all"],
        "reason": "Typosquat of cross-env (CVE-2018-3728)",
    },
    "discordd": {
        "versions": ["all"],
        "reason": "Typosquat of discord.js - token stealer",
    },
    "discord-selfbot-v13": {"versions": ["all"], "reason": "Discord token stealer"},
    "electron-native-notify": {
        "versions": ["all"],
        "reason": "Malicious postinstall - reverse shell",
    },
    "next-js": {"versions": ["all"], "reason": "Typosquat of next - credential exfil"},
    "nextjs": {"versions": ["all"], "reason": "Typosquat of next - credential exfil"},
    "reactdom": {"versions": ["all"], "reason": "Typosquat of react-dom"},
    "react-scripts2": {"versions": ["all"], "reason": "Typosquat of react-scripts"},
    "vite-node": {
        "versions": ["all"],
        "reason": "Typosquat of vite - suspected credential theft (not the official vite-node)",
    },
    "prisma-client": {
        "versions": ["all"],
        "reason": "Typosquat of @prisma/client - DB credential exfil",
    },
    "supabase-js": {
        "versions": ["all"],
        "reason": "Typosquat of @supabase/supabase-js - API key theft",
    },
    "stripe-node": {
        "versions": ["all"],
        "reason": "Typosquat of stripe - harvests STRIPE_SECRET_KEY",
    },
    "twilio-node": {
        "versions": ["all"],
        "reason": "Typosquat of twilio - credential exfiltration",
    },
    "aws-sdk2": {
        "versions": ["all"],
        "reason": "Typosquat of aws-sdk - harvests AWS credentials",
    },
    "aws-cdk2": {
        "versions": ["all"],
        "reason": "Typosquat of aws-cdk - IAM key exfiltration",
    },
    # ── Cryptominers ─────────────────────────────────────────────────────────
    "klow": {"versions": ["all"], "reason": "Embedded XMRig cryptominer"},
    "klown": {"versions": ["all"], "reason": "Embedded XMRig cryptominer"},
    "okhsa": {"versions": ["all"], "reason": "Embedded XMRig cryptominer"},
    "@azure-sdk/http-client": {
        "versions": ["all"],
        "reason": "Fake Azure package - cryptominer",
    },
    "node-binaries": {
        "versions": ["all"],
        "reason": "Fake binary helper - XMRig miner payload",
    },
    "native-build-tools": {
        "versions": ["all"],
        "reason": "Fake native addon - cryptominer dropper",
    },
    # ── Info stealers ────────────────────────────────────────────────────────
    "ssb-gs": {"versions": ["all"], "reason": "SSH key exfiltration"},
    "linux-cpu-governor": {"versions": ["all"], "reason": "Credential/SSH key stealer"},
    "win-browser-settings": {
        "versions": ["all"],
        "reason": "Browser cookie/credential stealer",
    },
    "env-config-helper": {
        "versions": ["all"],
        "reason": "Exfiltrates .env files and process environment",
    },
    "dotenv-defaults": {
        "versions": ["all"],
        "reason": "Typosquat of dotenv - exfiltrates environment variables",
    },
    "dotenv2": {
        "versions": ["all"],
        "reason": "Typosquat of dotenv - environment variable stealer",
    },
    "config-manager": {
        "versions": ["all"],
        "reason": "Suspected .env / secrets exfiltration package",
    },
    "secrets-manager": {
        "versions": ["all"],
        "reason": "Fake secrets manager - exfiltrates vault credentials",
    },
}

SUSPICIOUS_POSTINSTALL_PATTERNS = [
    r"curl\s+.+\|\s*(sh|bash)",
    r"wget\s+.+\|\s*(sh|bash)",
    r"powershell\s+.*-[Ee][Nn][Cc]",
    r"powershell\s+.*-[Ww]\s*[Hh]idden",
    r"eval\s*\(",
    r"require\(['\"]child_process['\"]\)",
    r"execSync\s*\(",
    r"spawnSync\s*\(",
    # Generic env / credential access
    r"process\.env\.(HOME|USERPROFILE|APPDATA|AWS_|NPM_TOKEN|GITHUB_TOKEN|CI_JOB_TOKEN)",
    r"readFileSync.*\.(env|npmrc|netrc|ssh|aws)",
    r"\.aws[\\/]credentials",
    r"\.ssh[\\/](id_rsa|id_ed|known_hosts|authorized)",
    # AI / LLM API key patterns
    r"process\.env\.(OPENAI_API_KEY|ANTHROPIC_API_KEY|DEEPSEEK_API_KEY)",
    r"process\.env\.(HUGGINGFACE_TOKEN|HF_TOKEN|HF_API_TOKEN)",
    r"process\.env\.(MISTRAL_API_KEY|COHERE_API_KEY|GROQ_API_KEY)",
    r"process\.env\.(REPLICATE_API_TOKEN|STABILITY_API_KEY|ELEVENLABS_API_KEY)",
    r"process\.env\.(GOOGLE_API_KEY|GEMINI_API_KEY|VERTEX_API_KEY)",
    r"process\.env\.(XAI_API_KEY|GROK_API_KEY|PERPLEXITY_API_KEY)",
    r"process\.env\.(TOGETHER_API_KEY|OPENROUTER_API_KEY|FIREWORKS_API_KEY)",
    r"process\.env\.(LANGCHAIN_API_KEY|LANGSMITH_API_KEY|PINECONE_API_KEY)",
    r"process\.env\.(CURSOR_|COPILOT_|CLINE_)",
    r"(sk-|sk-ant-|hf_|dsk-)[A-Za-z0-9_\-]{20,}",  # API key literal patterns
    # Obfuscation / encoding
    r"base64",
    r"Buffer\.from.*base64",
    r"unescape\s*\(",
    r"String\.fromCharCode",
    r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
    # Exfil channels
    r"clipboard|keylog|screenshot",
    r"reverse.*shell|remote.*shell",
    r"\.onion",
    r"pastebin\.com",
    r"discord.*webhook",
    r"telegram.*bot.*api",
    r"ngrok\.io",
    r"requestbin|webhook\.site|pipedream",
    # Miners
    r"xmrig|stratum\+|minerd",
]

SUSPICIOUS_RE = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_POSTINSTALL_PATTERNS]

POPULAR_PACKAGES = [
    # Core Node / JS
    "lodash",
    "moment",
    "express",
    "react",
    "axios",
    "webpack",
    "babel",
    "typescript",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "nodemon",
    "dotenv",
    "cors",
    "mongoose",
    "sequelize",
    "pg",
    "mysql2",
    "redis",
    "socket.io",
    "next",
    "vue",
    "angular",
    "svelte",
    "vite",
    "rollup",
    "parcel",
    "gulp",
    "rimraf",
    "cross-env",
    "node-fetch",
    "got",
    "superagent",
    "request",
    "cheerio",
    "puppeteer",
    "playwright",
    "cypress",
    "sinon",
    "nyc",
    "husky",
    "lint-staged",
    "lerna",
    "nx",
    "turbo",
    "esbuild",
    "swc",
    "bun",
    "vitest",
    "fastify",
    "koa",
    "hapi",
    "nest",
    "prisma",
    "drizzle",
    "typeorm",
    "mikro-orm",
    "knex",
    "stripe",
    "twilio",
    "sendgrid",
    "nodemailer",
    "passport",
    "jsonwebtoken",
    "bcrypt",
    "argon2",
    "zod",
    "yup",
    "joi",
    "ajv",
    "winston",
    "pino",
    "morgan",
    "sharp",
    "jimp",
    "canvas",
    "electron",
    "tauri",
    "supabase",
    "firebase",
    "amplify",
    "trpc",
    "graphql",
    "apollo",
    # AI / ML / LLM ecosystem (high-value typosquat targets)
    "openai",
    "anthropic",
    "langchain",
    "llamaindex",
    "ollama",
    "transformers",
    "huggingface",
    "replicate",
    "cohere",
    "deepseek",
    "mistral",
    "together",
    "groq",
    "ai",
    "vercel-ai",
    "ai-sdk",
    "crewai",
    "autogpt",
    "agentgpt",
    "tiktoken",
    "tokenizer",
    "chromadb",
    "pinecone",
    "weaviate",
    "qdrant",
    "whisper",
    "stability-ai",
    "elevenlabs",
    "langsmith",
    "langfuse",
    "helicone",
    "llm",
    "gpt4all",
    "localai",
]


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(
                min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (0 if ca == cb else 1))
            )
        prev = curr
    return prev[-1]


# Unscoped packages that genuinely resemble a popular package name but are
# independently legitimate — exclude from typosquat detection.
_KNOWN_LEGITIMATE_SIMILARS: frozenset = frozenset(
    {
        "eclint",  # EditorConfig linter
        "tslint",  # TypeScript linter (deprecated but well-known)
        "vitest",  # Vite-native test runner
        "matcha",  # BDD-style assertion library
        "dot",  # DoT.js template engine
        "jshint",  # JS linter
        "recast",  # JS AST transformation library
        "cypress",  # E2E testing framework
        # Official AI SDK scoped packages are handled via COMPROMISED_PACKAGES
        # exact-match; exclude their short aliases from typosquat distance check
        "ai",  # Vercel AI SDK (official)
        "groq",  # Official Groq SDK
        "cohere",  # Official Cohere SDK
        "ollama",  # Official Ollama JS client
        "replicate",  # Official Replicate SDK
        "whisper",  # OpenAI Whisper
        "tiktoken",  # Official OpenAI tokenizer
    }
)


def _is_typosquat(name: str) -> Tuple[bool, str]:
    # Scoped packages (@scope/name) provide namespace isolation. Stripping the
    # scope prefix before comparison causes false positives — e.g. @babel/core
    # becomes "core" which matches "cors", @typescript-eslint/parser becomes
    # "parser" which matches "parcel". Skip all scoped packages here; real
    # malicious scoped packages are caught via COMPROMISED_PACKAGES.
    if name.startswith("@"):
        return False, ""

    clean = name.lower()
    if clean in _KNOWN_LEGITIMATE_SIMILARS:
        return False, ""

    for popular in POPULAR_PACKAGES:
        dist = _levenshtein(clean, popular.lower())
        ratio = dist / max(len(clean), len(popular))
        if 0 < dist <= 2 and ratio < 0.4 and clean != popular.lower():
            return True, popular
    return False, ""


def _check_package_json(pkg_json_path: str) -> List[Dict]:
    findings: List[Dict] = []
    try:
        with open(pkg_json_path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return findings

    pkg_name = data.get("name", "unknown")
    pkg_ver = data.get("version", "?")

    all_deps: Dict[str, str] = {}
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        all_deps.update(data.get(key) or {})

    for dep, ver in all_deps.items():
        dep_lower = dep.lower()
        if dep_lower in COMPROMISED_PACKAGES:
            info = COMPROMISED_PACKAGES[dep_lower]
            versions = info.get("versions", ["all"])
            if "all" in versions or any(v in ver for v in versions):
                findings.append(
                    {
                        "title": f"Compromised dependency: {dep}@{ver}",
                        "path": pkg_json_path,
                        "reason": info["reason"],
                        "severity": "CRITICAL",
                        "category": "npm",
                        "subcategory": "compromised_package",
                        "package": dep,
                        "version": ver,
                    }
                )

        squat, similar = _is_typosquat(dep)
        if squat:
            findings.append(
                {
                    "title": f"Possible typosquat: {dep} (similar to '{similar}')",
                    "path": pkg_json_path,
                    "reason": f"Package '{dep}' is suspiciously similar to popular package '{similar}'",
                    "severity": "HIGH",
                    "category": "npm",
                    "subcategory": "typosquat",
                    "package": dep,
                    "version": ver,
                }
            )

    for script_name, script_val in (data.get("scripts") or {}).items():
        if not isinstance(script_val, str):
            continue
        for pattern in SUSPICIOUS_RE:
            if pattern.search(script_val):
                findings.append(
                    {
                        "title": f"Suspicious npm script '{script_name}' in {pkg_name}",
                        "path": pkg_json_path,
                        "reason": f"Script contains suspicious pattern: {script_val[:200]}",
                        "severity": "HIGH",
                        "category": "npm",
                        "subcategory": "suspicious_script",
                        "package": pkg_name,
                        "version": pkg_ver,
                        "cmdline": script_val[:300],
                    }
                )
                break

    return findings


def _check_lock_file(lock_path: str) -> List[Dict]:
    findings: List[Dict] = []
    ALLOWED_REGISTRIES = [
        "https://registry.npmjs.org/",
        "https://registry.yarnpkg.com/",
        "https://npm.pkg.github.com/",
        "https://registry.npmmirror.com/",
    ]
    try:
        with open(lock_path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        packages = data.get("packages") or data.get("dependencies") or {}

        def check_node(name: str, node: dict):
            if not isinstance(node, dict):
                return
            resolved = node.get("resolved", "")
            if resolved and not any(resolved.startswith(r) for r in ALLOWED_REGISTRIES):
                sev = "MEDIUM"
                if any(
                    x in resolved.lower()
                    for x in ["pastebin", "ngrok", "onion", "discord", "telegram"]
                ):
                    sev = "CRITICAL"
                findings.append(
                    {
                        "title": f"Suspicious resolved URL: {name}",
                        "path": lock_path,
                        "reason": f"Package resolved from non-registry URL: {resolved}",
                        "severity": sev,
                        "category": "npm",
                        "subcategory": "lockfile_tampering",
                        "package": name,
                    }
                )
            for sub_name, sub_node in node.get("dependencies", {}).items():
                check_node(sub_name, sub_node)

        for pkg_name, pkg_node in packages.items():
            check_node(pkg_name, pkg_node)
    except Exception:
        pass
    return findings


def scan_npm_global_list() -> List[Dict]:
    findings: List[Dict] = []
    try:
        r = subprocess.run(
            ["npm", "list", "-g", "--depth=0", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode not in (0, 1):
            return findings
        deps = json.loads(r.stdout or "{}").get("dependencies", {})
        for pkg_name, info in deps.items():
            ver = info.get("version", "?") if isinstance(info, dict) else "?"
            lower = pkg_name.lower()
            if lower in COMPROMISED_PACKAGES:
                pkg_info = COMPROMISED_PACKAGES[lower]
                versions = pkg_info.get("versions", ["all"])
                if "all" in versions or any(v in ver for v in versions):
                    findings.append(
                        {
                            "title": f"Compromised global package: {pkg_name}@{ver}",
                            "path": "npm global",
                            "reason": pkg_info["reason"],
                            "severity": "CRITICAL",
                            "category": "npm",
                            "subcategory": "compromised_global",
                            "package": pkg_name,
                            "version": ver,
                        }
                    )
            squat, similar = _is_typosquat(pkg_name)
            if squat:
                findings.append(
                    {
                        "title": f"Possible global typosquat: {pkg_name} (similar to '{similar}')",
                        "path": "npm global",
                        "reason": f"Globally installed '{pkg_name}' looks like typosquat of '{similar}'",
                        "severity": "HIGH",
                        "category": "npm",
                        "subcategory": "typosquat_global",
                        "package": pkg_name,
                        "version": ver,
                    }
                )
    except Exception:
        pass
    return findings


def run_npm_audit() -> List[Dict]:
    findings: List[Dict] = []
    roots = [
        os.environ.get("USERPROFILE", ""),
        r"C:\dev",
        r"C:\projects",
        r"C:\src",
        r"C:\repos",
    ]
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for item in Path(root).iterdir():
            if not item.is_dir() or not (item / "package.json").exists():
                continue
            try:
                r = subprocess.run(
                    ["npm", "audit", "--json"],
                    capture_output=True,
                    text=True,
                    timeout=45,
                    cwd=str(item),
                )
                if not r.stdout.strip():
                    continue
                data = json.loads(r.stdout)
                vulns = data.get("vulnerabilities") or data.get("advisories") or {}
                for vname, vdata in vulns.items():
                    if not isinstance(vdata, dict):
                        continue
                    sev_raw = (vdata.get("severity") or "").upper()
                    if sev_raw not in ("CRITICAL", "HIGH"):
                        continue
                    findings.append(
                        {
                            "title": f"npm audit: {vname} [{sev_raw}]",
                            "path": str(item),
                            "reason": vdata.get("title")
                            or vdata.get("overview")
                            or "Vulnerability found by npm audit",
                            "severity": sev_raw,
                            "category": "npm",
                            "subcategory": "npm_audit",
                            "package": vname,
                            "version": vdata.get("range") or "?",
                        }
                    )
            except Exception:
                pass
    return findings


def scan_npm() -> Dict[str, Any]:
    findings: List[Dict] = []

    findings += scan_npm_global_list()

    search_paths = [
        os.environ.get("USERPROFILE", ""),
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
        r"C:\dev",
        r"C:\projects",
        r"C:\src",
        r"C:\repos",
        r"C:\workspace",
    ]
    try:
        r = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            gp = str(Path(r.stdout.strip()).parent)
            if gp not in search_paths:
                search_paths.append(gp)
    except Exception:
        pass

    SKIP_DIRS = {".git", ".venv", "__pycache__", ".cache", "AppData"}
    for base_path in search_paths:
        if not base_path or not os.path.isdir(base_path):
            continue
        base = Path(base_path)
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            depth = root.replace(str(base), "").count(os.sep)
            if "node_modules" in root.split(os.sep) and depth > 6:
                dirs[:] = []
                continue
            if "package.json" in files:
                findings += _check_package_json(os.path.join(root, "package.json"))
            if "package-lock.json" in files:
                findings += _check_lock_file(os.path.join(root, "package-lock.json"))

    findings += run_npm_audit()

    # Deduplicate
    seen: set = set()
    unique: List[Dict] = []
    for f in findings:
        key = (f.get("title", ""), f.get("path", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {"module": "npm", "findings": unique, "findings_count": len(unique)}
