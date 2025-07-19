from openai import OpenAI
import os

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are NexFlow's personal AI recommendation engine. 
Given a brief patient description, output a short bulleted list of *personalized* metabolic health improvement tips. 
The recommendations should not be generic to the point where a patient already knows that they should be doing it 
but not too specific to the point where a user would be dissatisfied if they follow the recommendation and it doesn't work 
in the way that they expected. For each recommendation, provide a title or header of the recommendation, 
and give an impact factor (i.e. "High Impact", "Medium Impact", or "Low Impact"), and categorize it into one of the following 
categories: Diet, Exercise, Sleep, Lifestyle. Sort it based on impact (high impact 
advice should come first). Base your advice only on the user input.

This is the format your output should be in:
- Category: Impact: Header: Description
- Category: Impact: Header: Description

This is the patient description:
"""

def query_model(user_description: str, system_prompt: str = SYSTEM_PROMPT, model: str = "gpt-3.5-turbo") -> str:
    """
    Generate a response from OpenAI's GPT model given a prompt and system instructions.

    Args:
        user_description (str): User's input message.
        system_prompt (str): Instruction to guide model behavior.
        model (str): OpenAI model name (default: gpt-3.5-turbo)

    Returns:
        str: Model-generated response.
    """
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_description}
            ],
            temperature=0.7,
            max_tokens=300,
            top_p=0.95
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error: {e}"

# Example usage
if __name__ == "__main__":
    user_description = {
        "Age":40,
        "Gender":"Male",
        "Weight (lbs)":140,
        "Height (in.)": 70,
        "BMI":21.3,
        "Sleep":"6-7 hours, moderate quality",
        "Exercise":"3-5 hours/week, medium intensity"
    }
    print(query_model(str(user_description)))
