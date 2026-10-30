def evaluate_intelligence(context, confidence, actionability):

    score = 0

    if context.lower() == "yes":
        score += 1

    if confidence.lower() in ["high", "medium"]:
        score += 1

    if actionability.lower() == "yes":
        score += 1

    print("\nTHREAT INTELLIGENCE EVALUATION")

    print("Context:", context)
    print("Confidence:", confidence)
    print("Actionability:", actionability)

    print("Score:", score, "/ 3")

    if score == 3:

        print("Result: Genuine Threat Intelligence")

    elif score == 0:

        print("Result: Raw Data")

    else:

        print("Result: Incomplete Threat Intelligence")


print("THREAT INTELLIGENCE EVALUATOR")

context = input("Does the data have context? (yes/no): ")

confidence = input("Confidence level (high/medium/low): ")

actionability = input("Is the data actionable? (yes/no): ")

if context.lower() not in ["yes", "no"]:
    print("Invalid context input.")

elif confidence.lower() not in ["high", "medium", "low"]:
    print("Invalid confidence level.")

elif actionability.lower() not in ["yes", "no"]:
    print("Invalid actionability input.")

else:
    evaluate_intelligence(context, confidence, actionability)
