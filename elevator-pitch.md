The Big Picture: What are we looking at?

Imagine a company's databases as the secure archives of a library, and AI agents as researchers who keep showing up asking for documents. Today, most AI systems hand the researchers a master key: the AI decides for itself which archives to open and what to read. For low-stakes work that's fine. For medical records, classified data, or financial systems, it's terrifying.

Nautilus is the librarian at the front desk. No AI agent ever touches a database directly. Instead, the agent hands its request to Nautilus, and Nautilus does five things, every single time:

1. **Understands the request.** What is the agent actually asking for? What kind of data, about whom, how sensitive?
2. **Checks the rulebook.** Does this agent's clearance and stated purpose entitle it to this data? Which databases may the request touch, and which are off-limits? Critically, this decision is made by a deterministic rules engine (Fathom) — written-down policy, not AI judgment. The same request gets the same answer every time, and the answer can't be sweet-talked.
3. **Fetches only what's allowed.** Approved databases are queried with built-in restrictions — not just "yes, you can see the customer table," but "only the rows your scope permits."
4. **Signs a receipt.** Every routing decision gets a cryptographically signed token. Anyone can later verify — mathematically — that the decision happened exactly as recorded and wasn't forged or altered.
5. **Writes it in the logbook.** Every request, approval, denial, and error is appended to a tamper-evident audit log.

The standout feature: the librarian has a memory.

Most policy systems judge each request in isolation. Nautilus remembers the session. If an agent has already pulled personal data from three sources and now asks for a fourth, Nautilus can say "no — that's too much accumulated exposure." If Agent A, who holds secret clearance, tries to hand data to Agent B, who doesn't, Nautilus catches the handoff. If an agent's access pattern starts looking anomalous, it can escalate for human review.

Why is this important?

Companies want AI agents working with their real data, but "the AI decided to query the HR database" is not an answer that survives a compliance audit or a courtroom. Nautilus makes data access something you can *prove*: policy decides what's allowed, cryptography proves what happened, and the audit trail shows why. It turns AI data access from an act of faith into a matter of record.
