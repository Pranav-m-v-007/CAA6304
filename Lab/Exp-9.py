def classify_stage(description):

    description = description.lower()

    stages = {
        "Direction": ["objectives", "requirements", "planning", "priorities"],
        "Collection": ["collect", "gather", "logs", "data", "information"],
        "Processing": ["filter", "organize", "format", "clean", "sort"],
        "Analysis": ["analyze", "investigate", "identify", "interpret"],
        "Dissemination": ["share", "report", "distribute", "communicate"],
        "Feedback": ["feedback", "review", "improve", "suggestions"]
    }

    for stage, keywords in stages.items():
        if any(word in description for word in keywords):
            return stage

    return "Unknown Stage"


print("THREAT INTELLIGENCE LIFECYCLE CLASSIFIER")
activity = input("Enter intelligence team activity: ")

result = classify_stage(activity)

print("\nIdentified Lifecycle Stage:", result)
