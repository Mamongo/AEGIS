from app.models import finding


def model_allowed(model, policy):
    # A trailing colon explicitly permits the model family; other names match exactly.
    return any(model.startswith(name) if name.endswith(":") else model == name
               for name in policy.models.allow)


def evaluate_model(ctx, policy):
    if not model_allowed(ctx.model, policy):
        return [finding("model_policy", "MODEL_NOT_ALLOWED", "Requested model is not allowlisted")]
    return []
