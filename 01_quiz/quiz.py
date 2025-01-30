#!/usr/bin/python3

import json
import pathlib
import random

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--questions', help='JSON file containing quiz questions', type=pathlib.Path,
                                       default=pathlib.Path('questions.json'))
    args = parser.parse_args()

    assert args.questions.exists(), f'{args.questions} does not exist'

    random = random.SystemRandom()
    questions = json.loads(args.questions.read_text())
    assert isinstance(questions, list), 'JSON does not contain a list of questions'

    print('Welcome to our quiz! You have 120 seconds to answer all questions!')

    random.shuffle(questions)
    for question in questions:
        # Assume the first answer in the JSON is correct
        assert isinstance(question, dict), 'Question is not {"question": ..., "options": [...]}'
        assert 'question' in question, 'Question is not {"question": ..., "options": [...]}'
        assert 'options' in question, 'Question is not {"question": ..., "options": [...]}'
        assert isinstance(question['question'], str), 'Question is not a string'
        assert isinstance(question['options'], list), 'Answers are not a list'

        prompt = question['question']
        answers = question['options']

        assert len(answers) > 0, 'No answers for this question'
        correct = answers[0]

        random.shuffle(answers)
        print(prompt)
        for index, answer in enumerate(answers):
            print(f' ({index + 1}) {answer}')

        while True:
            number = input('> ')
            try:
                number = int(number)
            except ValueError:
                print(f'{number} is not a number')
                continue
            number -= 1
            if not 0 <= number < len(answers):
                print(f'{number + 1} is not one of the answers')
                continue
            break
        
        selected = answers[number]
        if selected != correct:
            print('Sorry, that\'s not the correct answer')
            exit(1)
        print()

    flag = pathlib.Path('/flag').read_text().strip()
    print('Congratulations, here is your flag:', flag)
