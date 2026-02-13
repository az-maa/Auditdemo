# AWB Audit Intelligence Platform — Project Description
## AI-Powered Security Audit System | Internship POC | Attijariwafa Bank

---

## Project Overview

The AWB Audit Intelligence Platform is a proof-of-concept agentic AI system built during an internship at Attijariwafa Bank. The goal of the project is to demonstrate how autonomous AI agents can be applied to real-world banking security operations — specifically to the monitoring, analysis, and response to security audit events.

The system combines a full-stack web application (React + Spring Boot) with a custom-built autonomous AI agent that can query a live PostgreSQL database, reason about security patterns, and take automated actions such as generating alerts, reports, and sending email notifications.

---

## Problem Statement

Banks generate thousands of audit events daily — logins, data accesses, transfers, errors, and more. Manually reviewing these events to detect suspicious behavior is time-consuming, error-prone, and reactive. Security analysts need a smarter tool that can proactively analyze patterns, flag anomalies, and explain its reasoning in plain language.

---

## Solution

An AI Security Analyst agent that:
- Has live read-only access to the bank's audit event database
- Can answer natural language questions like "Are there any suspicious users?" or "Show me off-hours activity"
- Reasons step by step, writes and executes its own SQL queries, and explains what it found
- Takes automated actions when threats are detected (alerts, emails, reports, manual review requests)
- Is accessible directly from a web dashboard — no terminal required

---

## System Architecture

The platform consists of three layers working together:

### 1. Frontend — React Web Application
- Built with React and styled with Tailwind-compatible CSS
- Dashboard showing real-time audit statistics: total events, success rate, failure count, critical issues
- Event list with filtering by type, status, and severity
- Search page for advanced event queries
- Statistics page with charts and trend analysis
- **AI Security Analyst chat panel** embedded in the dashboard — users can type questions and receive AI-generated analysis with visible reasoning steps

### 2. Backend — Spring Boot REST API
- Java Spring Boot application exposing a REST API
- Connects to a PostgreSQL database storing all audit events
- Provides endpoints for: fetching events, filtering by type/status/severity/date, statistics aggregation
- Includes a special `/api/audit/ask` endpoint that bridges the frontend to the Python AI agent — receives a natural language question, spawns the Python agent as a subprocess, passes credentials securely as environment variables, collects the structured output, and returns the answer + reasoning steps as JSON

### 3. AI Agent — Python ReAct Agent (No Framework)
- Built entirely from scratch without LangChain, LlamaIndex, or any agent framework
- Implements the ReAct (Reasoning + Acting) pattern manually: the agent alternates between thinking, calling tools, observing results, and deciding next steps
- Uses the Groq API with Llama 3.1 8B Instant as the language model
- Connects directly to PostgreSQL using psycopg2
- Outputs structured JSON lines (STEP_JSON) so the UI can display reasoning steps in real time

---

## The AI Agent in Detail

### What is a ReAct Agent?

ReAct (Reasoning + Acting) is an agentic AI pattern where a language model is given a set of tools and a problem. Instead of answering immediately, it reasons step by step: it decides which tool to call, calls it, observes the result, and decides what to do next — repeating until it has enough information to give a final answer.

### How This Agent Works

1. The user asks a question in the chat (e.g., "Which users have the highest failure rates?")
2. The agent receives the question and starts a ReAct loop
3. **Step 1 — Discovery:** The agent calls `list_tables()` and `get_table_schema()` to understand the database structure before writing any SQL
4. **Step 2 — Query:** The agent writes and executes a SQL SELECT query using `query_postgres()`. For global analysis, it uses GROUP BY, COUNT, and subqueries to compare users against averages
5. **Step 3 — Reasoning:** The agent reads the results, reasons about what is suspicious or notable, and decides whether to take action
6. **Step 4 — Action (if needed):** If threats are detected, the agent can call `create_security_alert()`, `send_email_alert()`, `generate_report()`, or `request_manual_review()`
7. **Final Answer:** The agent produces a plain-language summary of its findings

### Tools Available to the Agent

| Tool | Purpose |
|------|---------|
| `list_tables()` | Discover available tables in the database |
| `get_table_schema(table_name)` | Get column names and types before writing SQL |
| `query_postgres(query)` | Execute read-only SELECT queries |
| `get_distinct_statuses()` | Get valid status values to avoid errors |
| `create_security_alert(user_id, severity, reason)` | Create and save a security alert file |
| `send_email_alert(recipient, user_id, subject, body)` | Send a real email via SMTP |
| `generate_report(user_id, analysis)` | Generate a security analysis report |
| `request_manual_review(user_id, urgency, reason)` | Flag a case for human review |

### Key Design Decisions

- **No framework:** The ReAct loop, argument parser, tool dispatcher, and multi-turn conversation management are all written from scratch. This demonstrates a deep understanding of how agentic systems work under the hood.
- **SQL-first, no hallucination:** The agent is instructed to never invent data. Every claim must come from a tool result. If the database returns no rows, that is the answer.
- **Global analysis by default:** The system prompt instructs the agent to think across all users by default (using GROUP BY, averages, and ratios) rather than fixating on a single user.
- **Structured output:** The agent emits STEP_JSON lines during execution. The Java backend parses these and returns them to React as a structured steps array, enabling the UI to show a collapsible "reasoning trace" — the agent's thoughts and SQL results — alongside the final answer.
- **Safety guardrails:** The agent verifies user existence before taking any action, never repeats an action for the same user in one session, and only allows read-only SQL queries (INSERT, UPDATE, DELETE are blocked).

---

## Data Model

The core database table is `audit_events` with the following structure:

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT | Primary key |
| timestamp | TIMESTAMP | When the event occurred |
| event_type | VARCHAR | LOGIN, LOGOUT, DATA_ACCESS, TRANSFER, ERROR |
| user_id | VARCHAR | The user who triggered the event |
| action | TEXT | Human-readable description of what happened |
| resource | VARCHAR | The system resource accessed |
| ip_address | VARCHAR | Source IP address |
| status | VARCHAR | SUCCESS, FAILURE, PENDING |
| severity | VARCHAR | INFO, WARNING, ERROR, CRITICAL |
| details | TEXT | Additional context |

---

## Security Analysis Capabilities

The agent can detect the following patterns autonomously:

- **High failure rates:** Users with a disproportionate number of FAILURE status events compared to the global average
- **Off-hours activity:** Events occurring between 22:00 and 06:00 that may indicate unauthorized access
- **Unusual severity:** Users with an abnormal proportion of CRITICAL or HIGH severity events
- **Sensitive operations:** Event types involving DELETE, ADMIN, or UPDATE operations that warrant scrutiny
- **High event volume:** Users generating far more events than average in a short time window
- **Cross-user comparison:** All analysis compares individuals against system-wide averages computed dynamically from the database

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Frontend | React, Axios, React Router, CSS |
| Backend | Java 17, Spring Boot 3, Spring Data JPA |
| Database | PostgreSQL |
| AI Agent | Python 3, Groq API (Llama 3.1 8B Instant) |
| Agent Tools | psycopg2, smtplib, json, shlex |
| Build | Maven (backend), npm/Vite (frontend) |

---

## What Makes This Project Unique

1. **End-to-end integration:** The AI agent is not a standalone script — it is embedded in a production-style full-stack application with a real database, real API, and real UI.

2. **Built from scratch:** The ReAct agent loop, the argument parser that handles nested parentheses and quoted strings, the multi-turn conversation management, and the structured output format were all implemented without any AI agent framework.

3. **Transparent reasoning:** Unlike black-box AI systems, this agent shows its work. Every SQL query it runs and every observation it makes is visible to the user in the chat interface — building trust and auditability.

4. **Banking context:** The system is designed with real banking concerns in mind — regulatory compliance, fraud detection patterns, data minimization (read-only access), and the need for human review escalation.

5. **Autonomous action:** The agent does not just answer questions — it can take real actions (create alert files, send emails, generate reports) when its analysis warrants it, while maintaining strict guardrails to prevent false positives.

---

## Live Demo Scenario

A typical demo flow for the presentation:

1. Open the React dashboard — show live statistics (total events, failures, critical issues)
2. Navigate to the Events page — show the full audit log with filtering
3. Return to the dashboard — scroll to the AI Security Analyst chat panel
4. Ask: **"Are there any suspicious users?"**
   - The agent reasons out loud, queries the database, computes failure rates per user, checks for off-hours activity
   - The reasoning steps are visible (collapsible panel showing SQL queries and results)
   - The agent delivers a plain-language verdict
5. Ask: **"Show me all CRITICAL severity events"**
   - The agent queries, identifies affected users, and if warranted, creates a security alert and sends an email notification automatically
6. Show the generated alert file and email log as proof of autonomous action

---

## Project Scope and Limitations

This is a proof-of-concept built during an internship. Current limitations include:
- The database contains test/demo data, not real production events
- The Llama 3.1 8B model occasionally requires multiple reasoning steps for complex queries
- Email sending requires an SMTP server to be configured
- The agent runs as a subprocess (not a persistent service) — response time includes Python startup overhead

Future improvements could include: a persistent agent service (FastAPI), streaming responses to the UI, a larger/more capable model, integration with real bank security infrastructure, and role-based access control on the dashboard.
