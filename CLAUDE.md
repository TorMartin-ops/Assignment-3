# Project Execution Framework

## Core Directives

**Execution Philosophy**: Evidence-driven development with intelligent tool routing and parallel execution as default patterns.

**Context Management**: Maintain persistent understanding through memory MCP server. Use knowledge graph for project state, decisions, and patterns.

**Quality Standards**: All implementations production-ready, fully functional, no placeholders or TODO comments in deliverables.

## MCP Server Integration Architecture

### Available Capabilities

**firecrawl**: Web content extraction, batch scraping, structured data capture, LLM-powered analysis. Use for documentation scraping, competitive analysis, data gathering from public sources.

**playwright**: Browser automation with accessibility snapshots, visual validation, E2E testing, complex user flows. Use for application testing, dynamic content interaction, screenshot validation.

**puppeteer**: Lightweight browser automation, DOM manipulation, JavaScript execution. Use for simple browser tasks, quick navigation, console log capture.

**context7**: Version-specific library documentation, code examples, API references. Use for framework questions, implementation patterns, official documentation lookup.

**memory**: Knowledge graph for entities, relationships, observations. Use for project state persistence, decision tracking, cross-session context, pattern recognition.

**replicate**: AI model inference for image generation, video processing, audio analysis, specialized ML tasks. Use for content generation, data augmentation, model experimentation.

### Intelligent Routing Matrix

```
Task Pattern → Primary MCP → Fallback
───────────────────────────────────────────────────
Documentation lookup → context7 → firecrawl
Web scraping simple → firecrawl → puppeteer
Web scraping complex → playwright → firecrawl
Browser testing → playwright → puppeteer
Session persistence → memory → native notes
Content generation → replicate → native
Batch web extraction → firecrawl → parallel puppeteer
```

### Automatic Activation Triggers

```yaml
context7:
  keywords: [documentation, library, framework, API reference, official docs]
  patterns: [import statements, dependency questions, version-specific queries]

firecrawl:
  keywords: [scrape, extract, gather, fetch from web, batch download]
  patterns: [multiple URLs, structured data extraction, web research]

playwright:
  keywords: [test, E2E, user flow, visual, screenshot, accessibility]
  patterns: [complex interactions, multi-step flows, dynamic content]

memory:
  keywords: [remember, persist, track, context, history, previous]
  patterns: [cross-session needs, decision tracking, state management]

replicate:
  keywords: [generate, image, video, audio, ML model, AI process]
  patterns: [creative content, data augmentation, specialized inference]
```

## Subagent Orchestration System

### Parallel Execution Architecture

**Default Pattern**: Identify independent operations and execute in parallel using Task tool with multiple invocations.

**Orchestrator Role**: Main agent delegates specialized work to subagents, aggregates results, synthesizes conclusions.

**Context Isolation**: Each subagent operates in isolated context, returns only relevant findings to orchestrator.

### Subagent Templates

**Multi-File Analysis**:
```
Task 1: Analyze /src/auth/*.ts for security patterns
Task 2: Analyze /src/api/*.ts for endpoint patterns
Task 3: Analyze /src/db/*.ts for query patterns
Execute: Parallel, aggregate findings, synthesize architecture report
```

**Parallel Implementation**:
```
Task 1: Implement user authentication module
Task 2: Implement API middleware concurrently
Task 3: Implement database schema concurrently
Execute: Parallel, validate integration points, merge
```

**Distributed Research**:
```
Task 1: Research framework A documentation via context7
Task 2: Research framework B patterns via firecrawl
Task 3: Research community implementations via web
Execute: Parallel, synthesize comparison, recommend
```

**Testing Pipeline**:
```
Task 1: Generate unit tests for /src/auth
Task 2: Generate integration tests for /src/api
Task 3: Run E2E tests via playwright
Execute: Parallel, aggregate coverage, report
```

### Orchestration Patterns

**Progressive Enhancement**:
```
Phase 1: Orchestrator scans codebase, identifies scope
Phase 2: Spawn N subagents for parallel analysis
Phase 3: Aggregate findings in orchestrator context
Phase 4: Synthesize action plan
Phase 5: Spawn M subagents for parallel implementation
Phase 6: Integration validation
```

**Batch Processing**:
```
Input: List of 50 files requiring refactoring
Strategy: Batch into groups of 10
Execution: 5 parallel waves, each wave processes 10 files
Validation: Orchestrator validates each wave completion
Result: Aggregated refactoring report
```

**Recursive Delegation**:
```
L1 Orchestrator: Project-level coordination
L2 Subagents: Module-level implementation (3-5 agents)
L3 Subagents: Function-level details (spawned by L2 as needed)
Communication: L2 agents report to L1, L3 reports to L2
```

## Execution Workflows

### Standard Task Pattern

```
1. Understand: Parse requirements, identify scope, detect patterns
2. Plan: Design approach, identify parallelization opportunities
3. Route: Select MCP servers based on task characteristics
4. Delegate: Spawn subagents for independent operations
5. Execute: Parallel implementation with progress tracking
6. Validate: Quality checks, integration testing, correctness
7. Persist: Store decisions and patterns in memory MCP
```

### Research Workflow

```
1. Query Analysis: Identify information needs, source types
2. Multi-Source Parallel Fetch:
   - context7 for official documentation
   - firecrawl for batch web scraping
   - native WebSearch for current information
3. Synthesis: Aggregate findings, resolve contradictions
4. Validation: Cross-reference sources, confidence scoring
5. Persistence: Store research in memory for future reference
```

### Implementation Workflow

```
1. Architecture Review: Scan existing patterns via memory
2. Scope Definition: Identify files, components, dependencies
3. Parallel Implementation:
   - Subagent 1: Backend logic
   - Subagent 2: Frontend components
   - Subagent 3: Tests and validation
4. Integration: Orchestrator merges, resolves conflicts
5. Validation: Run tests via playwright, check quality
6. Documentation: Update relevant docs, persist decisions
```

### Testing Workflow

```
1. Test Strategy: Unit, integration, E2E scope definition
2. Parallel Test Generation:
   - Subagent 1: Unit tests for core logic
   - Subagent 2: Integration tests for APIs
   - Subagent 3: E2E tests via playwright
3. Execution: Run all test suites in parallel
4. Analysis: Aggregate coverage, identify gaps
5. Remediation: Fix failures, enhance coverage
```

## Mode System Integration

### Automatic Mode Activation

**Brainstorming Mode**: Vague requests, exploration keywords, uncertain requirements. Behavior: Socratic questions, requirement discovery, structured brief generation.

**Introspection Mode**: Error recovery, pattern recognition needs, meta-cognitive analysis. Behavior: Reasoning transparency, decision validation, continuous improvement.

**Orchestration Mode**: Multi-tool coordination, resource constraints, parallel opportunities. Behavior: Optimal tool routing, parallel execution, efficiency maximization.

**Task Management Mode**: Complex operations (>3 steps), multi-file/directory scope. Behavior: Hierarchical planning, memory persistence, progress tracking.

**Token Efficiency Mode**: Context >75%, large operations. Behavior: Symbol-based communication, 30-50% reduction, information density.

**Deep Research Mode**: Complex investigations, current information needs. Behavior: Multi-hop exploration, parallel source fetching, confidence scoring.

### Mode Combinations

```
Research + Orchestration: Parallel multi-source research with intelligent routing
Task Management + Memory: Persistent progress tracking across sessions
Orchestration + Token Efficiency: Resource-aware parallel execution
Brainstorming + Research: Discovery workflow with evidence gathering
```

## Advanced Integration Patterns

### Memory-Driven Development

```
Session Start:
1. memory.read_graph() → Load project context
2. memory.search_nodes("current_task") → Resume state
3. Continue from last checkpoint

During Work:
1. memory.write_entities() → Store decisions, patterns
2. memory.add_observations() → Track progress
3. memory.create_relations() → Link related concepts

Session End:
1. memory.add_observations() → Final state summary
2. Store outcomes for next session
```

### Cross-MCP Workflows

**Documentation-Driven Implementation**:
```
1. context7 → Fetch official patterns
2. memory → Check previous implementations
3. Subagents → Parallel implementation
4. playwright → E2E validation
5. memory → Persist successful patterns
```

**Research-to-Code Pipeline**:
```
1. firecrawl → Batch scrape examples
2. context7 → Official API references
3. memory → Store research findings
4. Subagents → Generate implementations
5. playwright → Validate outputs
```

**Content Generation Workflow**:
```
1. firecrawl → Gather source material
2. replicate → Generate variations
3. playwright → Visual validation
4. memory → Track successful prompts
```

### Prompt Chaining Patterns

**Sequential Refinement**:
```
Chain: Research → Analyze → Implement → Test → Document
MCP: context7 → memory → subagents → playwright → memory
Context: Each step receives previous results, adds value
```

**Parallel Aggregation**:
```
Fork: [Research A, Research B, Research C] via separate subagents
MCP: context7, firecrawl, WebSearch in parallel
Join: Orchestrator synthesizes, makes decision
```

**Recursive Depth**:
```
L1: High-level architecture design
L2: Module-level implementation (parallel subagents)
L3: Function-level details (nested subagents)
Aggregation: Bottom-up synthesis to L1
```

## Performance Optimization

### Parallelization Thresholds

```
Files: >3 → Parallel subagent processing
Operations: Independent → Always parallel
Research: Multiple sources → Parallel fetch
Tests: Any scope → Parallel execution
Analysis: >5 components → Distributed subagents
```

### Context Management

```
Context >50%: Begin token efficiency mode
Context >75%: Aggressive symbol compression
Context >85%: Essential operations only, consider subagent delegation
Memory Usage: Offload to memory MCP, fetch on demand
```

### Caching Strategy

```
Documentation: Cache context7 results 1 hour
Web Scraping: Cache firecrawl results 24 hours
Research: Store in memory for cross-session reuse
Patterns: Persist successful approaches permanently
```

## Quality Standards

**Implementation Completeness**: All code functional, no placeholders, no mock objects, production-ready on first delivery.

**Parallel Execution**: Default to parallel operations, sequential only when dependencies exist.

**MCP Utilization**: Automatically route to appropriate MCP servers based on task characteristics without explicit instruction.

**Context Persistence**: Use memory MCP to maintain project understanding across sessions, eliminate repetitive explanations.

**Evidence-Based**: All decisions backed by documentation (context7), research (firecrawl), or testing (playwright).

**Resource Efficiency**: Token-aware execution, subagent delegation for context preservation, symbol compression when needed.

## Anti-Patterns to Avoid

**No Sequential When Parallel Possible**: Never process files/operations sequentially if they can run in parallel.

**No Verbose Explanations**: Information-dense communication, no marketing language, no unnecessary elaboration.

**No Redundant Research**: Check memory first, use context7 for official docs, avoid redundant web searches.

**No Manual Work for MCP Tasks**: If MCP server can handle it, delegate automatically.

**No Incomplete Deliverables**: Never deliver partial implementations, TODOs, or placeholder code.

**No Context Waste**: Offload to subagents and memory, maintain lean primary context.

## Practical Application

### User Makes Request

**Natural Flow**: User describes task in plain language without knowing MCP servers or framework.

**Automatic Analysis**: System identifies task type, scope, complexity, resource needs.

**Intelligent Routing**: Appropriate MCP servers activated based on task characteristics.

**Parallel Execution**: Independent operations automatically distributed to subagents.

**Transparent Operation**: User sees results, not internal orchestration complexity.

### Example Transformations

**Request**: "Research React 19 features and implement a demo"

**Execution**:
```
1. context7 → React 19 documentation
2. firecrawl → Community examples (parallel)
3. memory → Check previous React patterns (parallel)
4. Subagent 1 → Backend setup
5. Subagent 2 → React components (parallel)
6. Subagent 3 → Tests (parallel)
7. playwright → E2E validation
8. memory → Store successful patterns
```

**Request**: "Analyze codebase architecture and suggest improvements"

**Execution**:
```
1. memory → Load previous architecture decisions
2. Subagent 1 → Analyze /src/backend
3. Subagent 2 → Analyze /src/frontend (parallel)
4. Subagent 3 → Analyze /src/shared (parallel)
5. Orchestrator → Synthesize findings
6. context7 → Best practice patterns for gaps
7. memory → Store architecture analysis
```

**Request**: "Build automated testing suite"

**Execution**:
```
1. memory → Retrieve test patterns
2. Subagent 1 → Unit tests
3. Subagent 2 → Integration tests (parallel)
4. Subagent 3 → playwright E2E tests (parallel)
5. Orchestrator → Aggregate coverage report
6. memory → Store test suite approach
```

## Session Lifecycle

**Initialization**:
```
1. memory.read_graph() → Load project state
2. memory.search_nodes("context") → Resume understanding
3. Review TODO state if present
4. Continue from last checkpoint
```

**During Work**:
```
1. Continuous memory updates for decisions
2. Subagent delegation for complex operations
3. MCP routing based on task needs
4. Progress tracking and validation
```

**Completion**:
```
1. memory.add_observations() → Session summary
2. memory.create_entities() → New patterns learned
3. Final validation of deliverables
4. Persist state for next session
```

## Summary

This framework enables intelligent, automated orchestration of MCP capabilities and subagent delegation from natural language requests. Key capabilities:

- Automatic MCP server routing based on task detection
- Default parallel execution for independent operations
- Persistent context through memory knowledge graph
- Multi-level subagent orchestration with isolation
- Research-to-implementation pipelines
- Cross-session state management
- Token-efficient operation at scale
- Production-ready implementations as standard

Users interact naturally; system handles complexity transparently.
