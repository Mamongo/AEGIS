from app.models import finding


def inspect(ctx, policy, args=None):
    results = []
    args = args or {}
    if ctx.user.role not in {"employee", "admin"} or ctx.agent.id != "support-agent":
        results.append(finding("authorization", "SEC-AUTHZ-001", "Unknown role or untrusted agent identity"))
    tenant = args.get("tenant") or (ctx.resource.tenant if ctx.resource else None)
    owner = args.get("user_id") or (ctx.resource.user_id if ctx.resource else None)
    if tenant and tenant != ctx.user.tenant:
        results.append(finding("authorization", "SEC-AUTHZ-002", "Cross-tenant resource access denied", severity="critical"))
    if owner and owner != ctx.user.id:
        results.append(finding("authorization", "SEC-AUTHZ-004", "Another user's private resource is not accessible"))
    if ctx.resource and ctx.resource.operation not in {"read", "update"}:
        results.append(finding("authorization", "SEC-AUTHZ-005", "Unknown resource operation"))
    if ctx.resource and ctx.resource.operation == "update" and ctx.user.role != "admin":
        results.append(finding("authorization", "SEC-AUTHZ-003", "Resource update requires administrator role"))
    if ctx.tool:
        rule = policy.tools.allow.get(ctx.tool.name)
        if rule is None:
            results.append(finding("authorization", "SEC-AUTHZ-003", "Tool has no explicit authorization grant"))
        elif (rule.roles and ctx.user.role not in rule.roles) or (rule.agents and ctx.agent.id not in rule.agents):
            results.append(finding("authorization", "SEC-AUTHZ-003", "Identity does not have permission for this tool"))
        elif rule.action != "allow":
            results.append(finding("tool_policy", "SEC-TOOL-001", "Tool action set by central policy", rule.action.upper()))
    return results
