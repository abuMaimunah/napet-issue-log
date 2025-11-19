#app.py

from flask import Flask, render_template, request, redirect, url_for 
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

#Database configuration
app.config['SECRET_KEY'] = 'your_secret_key'  #required for Flask-Login sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///issues.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)




login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

@app.context_processor
def inject_user():
	return dict(current_user=current_user)




#User model
class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(1200), unique=True, nullable=False)
	password = db.Column(db.String(200), nullable=False) #hashed password


#Database model
class Issue(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(100), nullable=False)
	description = db.Column(db.Text, nullable=False)
	resolution = db.Column(db.Text, nullable=True)
	priority = db.Column(db.String(20), nullable=False)
	status = db.Column(db.String(20), nullable=False)
	posted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) #Link to User
	user = db.relationship('User', backref='issues')
	
# Add ApprovalRequest model right after Issue
class ApprovalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default="Pending")  # Pending, Approved, Rejected

    issue = db.relationship('Issue', backref='approval_requests')
    requester = db.relationship('User', backref='requests')


#Create tables
with app.app_context():
	db.create_all()


@app.route("/")
@login_required
def home():
	issues = Issue.query.all() #fetch all issues from database
	return render_template("home.html", issues=issues)


@app.route("/create", methods=["GET", "POST"])
def create_issue():
	if request.method == "POST":
		title = request.form["title"]
		description = request.form["description"]
		priority = request.form["priority"]
		resolution = request.form["resolution"]
		status = request.form["status"]
		

		# Here you would typically save the issue to a database
		new_issue = Issue(title=title, description=description, priority=priority, resolution=resolution, status=status, posted_by=current_user.id)
		db.session.add(new_issue)
		db.session.commit()
		return redirect(url_for("home"))


		#return render_template("confirmation.html", title=title, 
		#					description=description, priority=priority, status=status)
	return render_template("create.html")

@app.route("/update/<int:issue_id>", methods=["POST"])
def update_issue(issue_id):
	issue = Issue.query.get_or_404(issue_id)
	if request.method == "POST":
		issue.status = "Resolved"
		db.session.commit()
		return redirect(url_for("home"))


@app.route("/approve/<int:request_id>")
@login_required
def approve_request(request_id):
    req = ApprovalRequest.query.get_or_404(request_id)
    if req.issue.posted_by != current_user.id:
        return "Not authorized", 403
    req.status = "Approved"
    db.session.commit()
    flash(f"Request from {req.requester.email} approved for issue '{req.issue.title}'.")
    return redirect(url_for("home"))

@app.route("/reject/<int:request_id>")
@login_required
def reject_request(request_id):
    req = ApprovalRequest.query.get_or_404(request_id)
    if req.issue.posted_by != current_user.id:
        return "Not authorized", 403
    req.status = "Rejected"
    db.session.commit()
    flash(f"Request from {req.requester.email} rejected for issue '{req.issue.title}'.")
    return redirect(url_for("home"))




from flask import flash

@app.route("/edit/<int:issue_id>", methods=["GET", "POST"])
@login_required
def edit_issue(issue_id):
    issue = Issue.query.get_or_404(issue_id)

    # Case 1: Owner can always edit
    if issue.posted_by != current_user.id:
        # Case 2: Non-owner → check if approved
        approved = ApprovalRequest.query.filter_by(
            issue_id=issue.id,
            requester_id=current_user.id,
            status="Approved"
        ).first()

        if not approved:
            # If not approved, create a new request
            existing_request = ApprovalRequest.query.filter_by(
                issue_id=issue.id,
                requester_id=current_user.id,
                status="Pending"
            ).first()

            if not existing_request:  # avoid duplicates
                new_request = ApprovalRequest(issue_id=issue.id, requester_id=current_user.id)
                db.session.add(new_request)
                db.session.commit()

            flash(f"Approval request for issue '{issue.title}' submitted by {current_user.email}. Waiting for owner approval.")
            return redirect(url_for("home"))

    # Case 3: Owner or approved requester → allow editing
    if request.method == "POST":
        issue.title = request.form["title"]
        issue.description = request.form["description"]
        issue.priority = request.form["priority"]
        issue.resolution = request.form["resolution"]
        issue.status = request.form["status"]
        db.session.commit()
        return redirect(url_for("home"))

    return render_template("edit.html", issue=issue)
#register route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")

        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html")


#login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("home"))
        else:
            return "Invalid credentials"
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))





if __name__ == "__main__":
	app.run(debug=True)
