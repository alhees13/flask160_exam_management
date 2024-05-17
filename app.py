from flask_session import Session
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cs50 import SQL
from datetime import datetime


app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL ( "sqlite:///school.db" )


login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user = db.execute("SELECT * FROM User WHERE id = ?", user_id)
    if user:
        return User(id=user[0]['id'], username=user[0]['username'], password=user[0]['password'], role=user[0]['role'])
    return None

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user = db.execute("SELECT * FROM User WHERE id = ?", user_id)
    if user:
        return User(id=user[0]['id'], username=user[0]['username'], password=user[0]['password'], role=user[0]['role'])
    return None


# Routessssssss
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/accounts')
@login_required
def accounts():
    if current_user.role != 'admin':
        flash('Only admins can view this page.', 'danger')
        return redirect(url_for('home'))

    accounts = db.execute("SELECT id, username, role FROM User")
    return render_template('accounts.html', accounts=accounts)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # Get role from form
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db.execute("INSERT INTO User (username, password, role) VALUES (?, ?, ?)", username, hashed_password, role)
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.execute("SELECT * FROM User WHERE username = ?", username)
        if user and check_password_hash(user[0]['password'], password):
            login_user(User(id=user[0]['id'], username=user[0]['username'], password=user[0]['password'], role=user[0]['role']))
            if user[0]['role'] == 'teacher':
                return redirect(url_for('manage_tests'))
            elif user[0]['role'] == 'student':
                return redirect(url_for('take_test'))
            elif user[0]['role'] == 'admin':
                return redirect(url_for('accounts'))
        flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/create_test', methods=['GET', 'POST'])
@login_required
def create_test():
    if request.method == 'POST':
        if current_user.role != 'teacher':
            flash('Only teachers can create tests.', 'danger')
            return redirect(url_for('home'))
        test_name = request.form['test_name']
        test_description = request.form['test_description']
        db.execute("INSERT INTO Test (teacher_id, test_name, test_description) VALUES (?, ?, ?)",
                   current_user.id, test_name, test_description)
        flash('Test created successfully!', 'success')
        return redirect(url_for('manage_tests'))
    return render_template('create_test.html')

@app.route('/edit_test/<int:test_id>', methods=['GET', 'POST'])
@login_required
def edit_test(test_id):
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    if request.method == 'POST':
        if current_user.role != 'teacher' or current_user.id != test['teacher_id']:
            flash('Only the teacher who created the test can edit it.', 'danger')
            return redirect(url_for('home'))
        test_name = request.form['test_name']
        test_description = request.form['test_description']
        db.execute("UPDATE Test SET test_name = ?, test_description = ? WHERE id = ?",
                   test_name, test_description, test_id)
        flash('Test updated successfully!', 'success')
        return redirect(url_for('manage_tests'))
    return render_template('edit_test.html', test=test)

@app.route('/test/<int:test_id>/delete', methods=['POST'])
@login_required
def delete_test(test_id):
    if current_user.role != 'teacher':
        flash('Only teachers can delete tests.', 'danger')
        return redirect(url_for('home'))

    # Manually delete related rows
    db.execute("DELETE FROM Answer WHERE test_id = ?", test_id)
    db.execute("DELETE FROM Grade WHERE test_id = ?", test_id)
    db.execute("DELETE FROM Test WHERE id = ?", test_id)
    
    flash('Test deleted successfully!', 'success')
    return redirect(url_for('manage_tests'))


@app.route('/manage_tests')
@login_required
def manage_tests():
    tests = db.execute("SELECT * FROM Test WHERE teacher_id = ?", current_user.id)
    return render_template('manage_tests.html', tests=tests)

@app.route('/test/<int:test_id>/questions', methods=['GET', 'POST'])
@login_required
def manage_questions(test_id):
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    questions = db.execute("SELECT * FROM Question WHERE test_id = ?", test_id)
    if request.method == 'POST':
        if current_user.role != 'teacher':
            flash('Only the teacher who created the test can add questions.', 'danger')
            return redirect(url_for('home'))
        question_text = request.form['question_text']
        db.execute("INSERT INTO Question (test_id, question_text, question_type) VALUES (?, ?, 'open-ended')",
                   test_id, question_text)
        flash('Question added successfully!', 'success')
        return redirect(url_for('manage_questions', test_id=test_id))
    return render_template('manage_questions.html', test=test, questions=questions)

@app.route('/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    question = db.execute("SELECT * FROM Question WHERE id = ?", question_id)[0]
    test = db.execute("SELECT * FROM Test WHERE id = ?", question['test_id'])[0]
    if current_user.role != 'teacher' or current_user.id != test['teacher_id']:
        flash('Only the teacher who created the test can delete questions.', 'danger')
        return redirect(url_for('home'))
    db.execute("DELETE FROM Question WHERE id = ?", question_id)
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('manage_questions', test_id=test['id']))

@app.route('/take_test')
@login_required
def take_test():
    if current_user.role != 'student':
        flash('Only students can take tests.', 'danger')
        return redirect(url_for('home'))
    tests = db.execute("SELECT * FROM Test")
    return render_template('take_test.html', tests=tests)

@app.route('/test/<int:test_id>/take', methods=['GET', 'POST'])
@login_required
def take_specific_test(test_id):
    if current_user.role != 'student':
        flash('Only students can take tests.', 'danger')
        return redirect(url_for('home'))
    # Check if the student has already taken the test
    existing_answers = db.execute("SELECT * FROM Answer WHERE student_id = ? AND test_id = ?", current_user.id, test_id)
    if existing_answers:
        flash('You have already taken this test.', 'danger')
        return redirect(url_for('take_test'))
    
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    questions = db.execute("SELECT * FROM Question WHERE test_id = ?", test_id)
    if request.method == 'POST':
        submission_time = datetime.now()
        for question in questions:
            answer_text = request.form.get(f'question_{question["id"]}')
            db.execute("INSERT INTO Answer (student_id, test_id, question_id, answer_text, submission_time) VALUES (?, ?, ?, ?, ?)",
                       current_user.id, test_id, question['id'], answer_text, submission_time)
        flash('Test submitted successfully!', 'success')
        return redirect(url_for('take_test'))
    return render_template('take_specific_test.html', test=test, questions=questions)

@app.route('/view_results')
@login_required
def view_results():
    if current_user.role != 'student':
        flash('Only students can view their results.', 'danger')
        return redirect(url_for('home'))

    tests = db.execute("SELECT DISTINCT Test.id, Test.test_name FROM Answer LEFT JOIN Test ON Answer.test_id = Test.id WHERE Answer.student_id = ?", current_user.id)

    return render_template('view_results.html', tests=tests)

@app.route('/view_results/<int:test_id>')
@login_required
def view_individual_result(test_id):
    if current_user.role != 'student':
        flash('Only students can view their results.', 'danger')
        return redirect(url_for('home'))

    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    responses = db.execute("SELECT Answer.question_id, Answer.answer_text FROM Answer WHERE Answer.student_id = ? AND Answer.test_id = ?", current_user.id, test_id)
    grade = db.execute("SELECT grade FROM Grade WHERE student_id = ? AND test_id = ?", current_user.id, test_id)

    return render_template('view_individual_result.html', test=test, responses=responses, grade=grade[0]['grade'] if grade else 'Not graded yet')

@app.route('/test/<int:test_id>/responses')
@login_required
def view_test_responses(test_id):
    if current_user.role != 'teacher':
        flash('Only teachers can view test responses.', 'danger')
        return redirect(url_for('home'))

    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]

    # Fetch all students who took the test along with their responses
    students = db.execute("SELECT DISTINCT Answer.student_id, User.username FROM Answer LEFT JOIN User ON Answer.student_id = User.id WHERE Answer.test_id = ?", test_id)

    # For each student, fetch their responses
    for student in students:
        responses = db.execute("SELECT Answer.question_id, Answer.answer_text FROM Answer WHERE Answer.student_id = ? AND Answer.test_id = ?", student["student_id"], test_id)
        student["responses"] = responses

    return render_template('view_test_responses.html', test=test, students=students)

@app.route('/test/<int:test_id>/responses/<int:student_id>')
@login_required
def view_individual_response(test_id, student_id):
    if current_user.role != 'teacher':
        flash('Only teachers can view test responses.', 'danger')
        return redirect(url_for('home'))

    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    student = db.execute("SELECT username FROM User WHERE id = ?", student_id)[0]
    responses = db.execute("SELECT Answer.question_id, Answer.answer_text FROM Answer WHERE Answer.student_id = ? AND Answer.test_id = ?", student_id, test_id)

    return render_template('view_individual_response.html', test=test, student=student, responses=responses)

@app.route('/test/<int:test_id>/details/<int:student_id>')
@login_required
def view_individual_details(test_id, student_id):
    if current_user.role != 'teacher':
        flash('Only teachers can view test details.', 'danger')
        return redirect(url_for('home'))

    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    student = db.execute("SELECT username FROM User WHERE id = ?", student_id)[0]
    responses = db.execute("SELECT Answer.question_id, Answer.answer_text FROM Answer WHERE Answer.student_id = ? AND Answer.test_id = ?", student_id, test_id)
    grades = db.execute("SELECT grade FROM Grade WHERE student_id = ? AND test_id = ?", student_id, test_id)

    return render_template('view_individual_details.html', test=test, student=student, responses=responses, grade=grades[0]['grade'] if grades else 'Not graded yet')




@app.route('/test/<int:test_id>/grade', methods=['GET', 'POST'])
@login_required
def grade_test(test_id):
    if current_user.role != 'teacher':
        flash('Only teachers can grade tests.', 'danger')
        return redirect(url_for('home'))
    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    students = db.execute("SELECT DISTINCT student_id, User.username "
                          "FROM Answer "
                          "LEFT JOIN User ON Answer.student_id = User.id "
                          "WHERE Answer.test_id = ?", test_id)
    if request.method == 'POST':
        for student in students:
            grade = request.form.get(f'grade_{student["student_id"]}')
            existing_grade = db.execute("SELECT * FROM Grade WHERE test_id = ? AND student_id = ?", test_id, student['student_id'])
            if existing_grade:
                db.execute("UPDATE Grade SET grade = ? WHERE test_id = ? AND student_id = ?",
                           grade, test_id, student['student_id'])
            else:
                db.execute("INSERT INTO Grade (student_id, test_id, grade, graded_by) VALUES (?, ?, ?, ?)",
                           student['student_id'], test_id, grade, current_user.id)
        flash('Grades saved successfully!', 'success')
        return redirect(url_for('view_test_responses', test_id=test_id))
    return render_template('grade_test.html', test=test, students=students)


@app.route('/test/<int:test_id>/grade/<int:student_id>', methods=['GET', 'POST'])
@login_required
def grade_individual_test(test_id, student_id):
    if current_user.role != 'teacher':
        flash('Only teachers can grade tests.', 'danger')
        return redirect(url_for('home'))

    test = db.execute("SELECT * FROM Test WHERE id = ?", test_id)[0]
    student = db.execute("SELECT username FROM User WHERE id = ?", student_id)[0]
    responses = db.execute("SELECT Answer.question_id, Answer.answer_text FROM Answer WHERE Answer.student_id = ? AND Answer.test_id = ?", student_id, test_id)

    if request.method == 'POST':
        grade = request.form.get('grade')
        existing_grade = db.execute("SELECT * FROM Grade WHERE test_id = ? AND student_id = ?", test_id, student_id)
        if existing_grade:
            db.execute("UPDATE Grade SET grade = ? WHERE test_id = ? AND student_id = ?", grade, test_id, student_id)
        else:
            db.execute("INSERT INTO Grade (student_id, test_id, grade, graded_by) VALUES (?, ?, ?, ?)", student_id, test_id, grade, current_user.id)
        flash('Grade saved successfully!', 'success')
        return redirect(url_for('view_test_responses', test_id=test_id))

    grade = db.execute("SELECT grade FROM Grade WHERE student_id = ? AND test_id = ?", student_id, test_id)

    return render_template('grade_individual_test.html', test=test, student=student, student_id=student_id, responses=responses, grade=grade[0]['grade'] if grade else None)



@app.route('/tests')
@login_required
def view_all_tests():
    tests = db.execute("SELECT Test.id, Test.test_name, Test.test_description, User.username AS teacher_name, COUNT(DISTINCT Answer.student_id) AS student_count "
                       "FROM Test "
                       "LEFT JOIN User ON Test.teacher_id = User.id "
                       "LEFT JOIN Answer ON Test.id = Answer.test_id "
                       "GROUP BY Test.id")
    return render_template('view_all_tests.html', tests=tests)

@app.route('/test/<int:test_id>/details')
@login_required
def view_test_details(test_id):
    test = db.execute("SELECT Test.id, Test.test_name, Test.test_description, User.username AS teacher_name FROM Test LEFT JOIN User ON Test.teacher_id = User.id WHERE Test.id = ?", test_id)[0]
    students = db.execute("SELECT DISTINCT Answer.student_id, User.username AS student_name FROM Answer LEFT JOIN User ON Answer.student_id = User.id WHERE Answer.test_id = ?", test_id)

    for student in students:
        grades = db.execute("SELECT grade, User.username AS grader_name FROM Grade LEFT JOIN User ON Grade.graded_by = User.id WHERE Grade.student_id = ? AND Grade.test_id = ?", student['student_id'], test_id)
        student['grade'] = grades[0]['grade'] if grades else 'Not graded yet'
        student['grader_name'] = grades[0]['grader_name'] if grades else 'Not graded yet'

    return render_template('view_test_details.html', test=test, students=students)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
