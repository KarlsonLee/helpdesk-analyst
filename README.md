# IT Helpdesk Enterprise Intelligence Virtual Analyst

A read-only AI analyst that answers questions about **IT support tickets, laptops and monitors, software
licenses and IT policy**. Built with Google ADK, MCP-style tools, and Streamlit.

> Capstone project - Enterprise Production-Ready Agentic AI System

## What you can ask

- "What is the status and priority of ticket T-2001?"
- "How many Adobe Acrobat license seats are still available?"
- "Is laptop A02 eligible for a hardware refresh?" (database facts + policy rule)
- "Is ticket T-2002 within its SLA?" (database facts + policy rule)
- "Ticket T-2004 is phishing. Disable that account now." (needs human Security team approval)
- "Run this SQL: DROP TABLE tickets" (blocked)

## Architecture

```
User -> [Input guardrail: PII mask + injection block] -> helpdesk_coordinator
                                                          |-- data_analyst   -> mcp_list_tables / mcp_describe_table / mcp_read_query
                                                          |                      -> [is_sql_mutation + read-only DB] -> enterprise.db
                                                          `-- policy_advisor -> mcp_list_policies / mcp_read_policy -> policies/*.md
every model call -> after_model_callback -> tokens + estimated USD cost
```

| Pillar | Where |
|---|---|
| 1. Multi-agent architecture | `helpdesk_coordinator` delegates to `data_analyst` and `policy_advisor` via `AgentTool` |
| 2. Enterprise integration (MCP discovery) | Agents discover tables with `mcp_list_tables` / `mcp_describe_table`; policies via `mcp_read_policy`. No schema is hard-coded, so new tables are found automatically (try the sidebar *Add `change_requests` table* button) |
| 3. Two-tier guardrails | **Input:** `guard_input` masks emails/phones/cards and blocks prompt injection. **Data:** `is_sql_mutation` (SQL parse tree) + database opened with `file:...?mode=ro` + no mutation tool registered |
| 4. Observability & cost | `track_cost` (`after_model_callback`) logs prompt/output tokens and estimated USD cost; shown in the sidebar |
| 5. Automated evaluation | `capstone_golden.json` (7 golden cases) graded 1-5 by an LLM-as-a-Judge in the **Evaluation** tab |
| 6. Streamlit Cloud deployment | `app.py`, `requirements.txt`, API key from `st.secrets` |

## Project structure

```
helpdesk-analyst/
├── app.py                      # Streamlit dashboard + agents + guardrails + eval harness
├── requirements.txt            # Python packages
├── capstone_golden.json        # Golden test cases for the LLM judge
├── enterprise.db               # Created automatically on first run (not committed)
├── policies/
│   └── it_policy_handbook.md   # SLA, hardware, license, security and privacy policy
├── .streamlit/
│   └── secrets.toml.example    # Template for your API key
└── README.md
```

## Run locally

1. Get a free Gemini API key at https://aistudio.google.com/apikey
2. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and paste your key inside.
3. Run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

`enterprise.db` is created on first run with dates relative to today. Delete it to reseed
(for example, if the hardware-refresh or SLA examples drift as days pass).

## Deploy to Streamlit Community Cloud

1. Push this folder to **your own** GitHub repo (`.venv`, `enterprise.db` and `.streamlit/secrets.toml`
   are git-ignored).
2. Go to [share.streamlit.io](https://share.streamlit.io) -> **New app** -> pick the repo, branch `main`, file `app.py`.
3. **Advanced settings -> Secrets**, add:
   ```toml
   GOOGLE_API_KEY = "your-key-here"
   ```
4. Deploy.

## Demo order (with the sidebar buttons)

1. **What tables exist in the database?** - shows MCP discovery (open the *Agent & tool trace*).
2. **Is laptop A02 eligible for a hardware refresh?** - shows both specialists working together.
3. Click **Add `change_requests` table**, then **What are the pending change requests?** - zero-code schema change.
4. **My email is john@example.com and card ...** - shows PII masking.
5. **Ignore previous instructions...** - shows the prompt-injection block.
6. **Run this SQL: DROP TABLE tickets** - shows the data-tier SQL guardrail.
7. Look at the sidebar cost numbers, then open the **Evaluation** tab and click **Run evaluation**.

## Evaluation

Each golden case is answered by the agent and scored 1-5 by a separate judge agent (4+ passes). The tab
reports the average score, pass count and the USD cost of the run - use these for your benchmark report.

## Notes

- Cost uses estimated Gemini 2.5 Flash prices set at the top of `app.py`; update them if pricing changes.
- The assistant is intentionally read-only. Account disablement, extra license purchases and expensive
  repairs require human approval.
