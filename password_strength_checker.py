import re

def assess_password_strength(password):
    strength_score = 0
    feedback = []
    issues = [] 
    min_length = 8
    has_uppercase = False
    has_lowercase = False
    has_digit = False
    has_special = False

    special_characters_set = set("!@#$%^&*()-_+=[]{}|;:'\",.<>/?`~")


    # Check Length
    if len(password) >= min_length:
        strength_score += 1
    else:
        issues.append(f"Length: Password should be at least {min_length} characters long.")

    # Check for Character Types using regex for robustness

    if re.search(r"[A-Z]", password):
        has_uppercase = True
        strength_score += 1
    else:
        issues.append("Uppercase: Include at least one uppercase letter.")

    if re.search(r"[a-z]", password):
        has_lowercase = True
        strength_score += 1
    else:
        issues.append("Lowercase: Include at least one lowercase letter.")

    if re.search(r"\d", password): # \d matches any digit (0-9)
        has_digit = True
        strength_score += 1
    else:
        issues.append("Numbers: Include at least one number.")

    # Check for special characters using a loop or regex
    if any(char in special_characters_set for char in password):
        has_special = True
        strength_score += 1
    else:
        # example special characters
        example_special_chars = "".join(list(special_characters_set)[:5])
        issues.append(f"Special Characters: Include at least one special character (e.g., {example_special_chars}...).")

    # Determine Overall Strength
    if strength_score == 5:
        overall_strength = "Very Strong"
        feedback.append("Excellent! Your password meets all recommended criteria.")
    elif strength_score == 4:
        overall_strength = "Strong"
        feedback.append("Good! Your password is strong, but could be even better.")
    elif strength_score == 3:
        overall_strength = "Moderate"
        feedback.append("Your password is moderate. Consider adding more complexity.")
    elif strength_score == 2:
        overall_strength = "Weak"
        feedback.append("Your password is weak. It's easily guessable.")
    else: # 0 or 1
        overall_strength = "Very Weak"
        feedback.append("Your password is very weak. Please choose a stronger one!")

    return {
        "score": strength_score,
        "overall_strength": overall_strength,
        "feedback_summary": feedback,
        "issues": issues 
    }

def main():
    print("Password Strength Assessor")
    print("Criteria: Length >= 8, Uppercase, Lowercase, Numbers, Special Characters")
    print("Enter a password to assess its strength. Type 'exit' to quit.")

    while True:
        password = input("\nEnter your password: ")
        if password.lower() == 'exit':
            break

        if not password:
            print("Please enter a password.")
            continue

        result = assess_password_strength(password)

        print("\n Assessment Result:- ")
        print(f"Overall Strength: {result['overall_strength']} ({result['score']}/5 criteria met)")
        print(result['feedback_summary'][0]) 

        if result['issues']:
            print("To improve your password, address the following:")
            for item in result['issues']:
                print(f"- {item}")
        else:
            print("No specific issues found. Your password is very strong!")

if __name__ == "__main__":
    main()