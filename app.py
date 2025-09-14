# app.py (full) - updated with change-password facility
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, Response
import sqlite3, os, io, csv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

APP_SECRET = 'change_this_secret'
# built-in admin credentials (also allowed to create accounts)
ADMIN_USER = 'admin'
ADMIN_PASS = 'Mo980616'
DB_PATH = 'maintenance.db'

MONTHS = [
    ('aug_2025', '2025-08', 'August 2025'),
    ('sep_2025', '2025-09', 'September 2025'),
    ('oct_2025', '2025-10', 'October 2025'),
    ('nov_2025', '2025-11', 'November 2025'),
    ('dec_2025', '2025-12', 'December 2025')
]

TOTAL_HOUSES = 60

# Roles driven from here and passed to admin template
ROLES = [
    ('admin', 'Admin (full access, can manage users)'),
    ('maintenance', 'Maintenance (can add maintenance records only)'),
    ('expenditure', 'Expenditure (can add expenditure records only)')
]

app = Flask(__name__, template_folder='templates')
app.secret_key = APP_SECRET

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ---------------------------
# Permission helpers & decorator
# ---------------------------
def is_builtin_admin():
    """Return True if session indicates builtin admin signed in."""
    return session.get('username') == ADMIN_USER and session.get('role') == 'admin'

def require_roles(*allowed_roles):
    """
    Decorator to require one of the allowed roles.
    Usage: @require_roles('admin', 'maintenance')
    Built-in admin user (username == ADMIN_USER) always allowed.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # builtin admin always allowed
            if is_builtin_admin():
                return f(*args, **kwargs)

            role = session.get('role')
            if role in allowed_roles:
                return f(*args, **kwargs)

            flash('You do not have permission to access that page. Please log in with an account that has the necessary role.')
            return redirect(url_for('login'))
        return wrapped
    return decorator

def only_admin_required():
    """
    Inline check used in admin panel routes (return True/False).
    """
    if is_builtin_admin():
        return True
    return session.get('role') == 'admin'

def login_required(f):
    """
    Simple decorator to ensure user is logged in (either builtin admin or a DB user).
    Redirects to login page otherwise.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('username'):
            return f(*args, **kwargs)
        flash('You must be logged in to access that page.')
        return redirect(url_for('login'))
    return wrapped

# ---------------------------
# Routes
# ---------------------------
@app.route('/')
def index():
    db = get_db()
    records = {}
    totals = {}
    expenditures_total = {}

    month_mapping = {}
    for display_key, db_key, label in MONTHS:
        month_mapping[display_key] = db_key

        cur = db.execute('SELECT * FROM records WHERE month = ? ORDER BY house_number', (db_key,))
        rows = cur.fetchall()
        records[display_key] = rows

        tot_cur = db.execute('SELECT SUM(amount) as s FROM records WHERE month = ? AND amount IS NOT NULL', (db_key,))
        payments_sum = tot_cur.fetchone()['s'] or 0

        exp_cur = db.execute('SELECT SUM(amount) as s FROM expenditures WHERE month = ?', (db_key,))
        exp_sum = exp_cur.fetchone()['s'] or 0
        expenditures_total[display_key] = int(exp_sum)

        totals[display_key] = int(payments_sum) - int(exp_sum)

    return render_template('index.html',
                           months=[(k, label) for k, _, label in MONTHS],
                           records=records,
                           totals=totals,
                           expenditures_total=expenditures_total,
                           month_mapping=month_mapping)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')

        # check built-in admin first
        if u == ADMIN_USER and p == ADMIN_PASS:
            session['role'] = 'admin'
            session['username'] = ADMIN_USER
            flash('Signed in as admin')
            return redirect(url_for('index'))

        # check users table
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE username = ?', (u,))
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], p):
            session['role'] = user['role'] or 'admin'
            session['username'] = user['username']
            flash(f"Signed in as {user['username']}")
            return redirect(url_for('index'))

        flash('Invalid credentials')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('role', None)
    session.pop('username', None)
    flash('Logged out')
    return redirect(url_for('index'))

# ----------------------
# Maintenance (payments) routes
# - /add: allowed for 'admin' and 'maintenance'
# - edit/delete: admin-only
# ----------------------
@app.route('/add', methods=['GET','POST'])
@require_roles('admin', 'maintenance')
def add():
    if request.method == 'POST':
        try:
            house = int(request.form.get('house_number'))
        except Exception:
            flash('Invalid house number')
            return redirect(url_for('add'))

        month = request.form.get('month')  # db key
        date_paid = request.form.get('date_paid') or None
        amount = request.form.get('amount')
        try:
            amount = int(amount)
        except Exception:
            amount = None
        db = get_db()
        db.execute('UPDATE records SET date_paid = ?, amount = ? WHERE house_number = ? AND month = ?', (date_paid, amount, house, month))
        db.commit()
        flash('Payment added/updated')
        return redirect(url_for('index'))

    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('add.html', total_houses=TOTAL_HOUSES, months=month_options)

@app.route('/edit/<int:rec_id>', methods=['GET','POST'])
@require_roles('admin')
def edit(rec_id):
    db = get_db()
    cur = db.execute('SELECT * FROM records WHERE id = ?', (rec_id,))
    rec = cur.fetchone()
    if not rec:
        flash('Record not found')
        return redirect(url_for('index'))
    if request.method == 'POST':
        month = request.form.get('month')
        date_paid = request.form.get('date_paid') or None
        amount = request.form.get('amount')
        try:
            amount = int(amount) if amount != '' else None
        except Exception:
            amount = None
        db.execute('UPDATE records SET month = ?, date_paid = ?, amount = ? WHERE id = ?', (month, date_paid, amount, rec_id))
        db.commit()
        flash('Record saved')
        return redirect(url_for('index'))

    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('edit.html', rec=rec, months=month_options)

@app.route('/delete/<int:rec_id>')
@require_roles('admin')
def delete(rec_id):
    db = get_db()
    db.execute('UPDATE records SET date_paid = NULL, amount = NULL WHERE id = ?', (rec_id,))
    db.commit()
    flash('Record cleared')
    return redirect(url_for('index'))

# ----------------------
# Export routes
# ----------------------
@app.route('/export/<month_key>')
def export_month(month_key):
    db_key = None
    for display_key, database_key, _ in MONTHS:
        if display_key == month_key:
            db_key = database_key
            break
    if not db_key:
        flash('Invalid month')
        return redirect(url_for('index'))

    db = get_db()
    cur = db.execute('SELECT house_number, date_paid, amount FROM records WHERE month = ? ORDER BY house_number', (db_key,))
    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['House', 'Date Paid', 'Amount'])
    for r in rows:
        cw.writerow([r['house_number'], r['date_paid'] if r['date_paid'] is not None else '', r['amount'] if r['amount'] is not None else ''])
    output = si.getvalue()
    filename = f"payments_{db_key}.csv"
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{filename}"'})

@app.route('/export_year/<year>')
def export_year(year):
    db = get_db()
    cur = db.execute('SELECT house_number, month, date_paid, amount FROM records WHERE substr(month,1,4)=? ORDER BY month, house_number', (year,))
    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['House','Month','Date Paid','Amount'])
    for r in rows:
        cw.writerow([r['house_number'], r['month'], r['date_paid'] if r['date_paid'] else '', r['amount'] if r['amount'] is not None else ''])
    output = si.getvalue()
    filename = f"payments_{year}.csv"
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{filename}"'})

# ----------------------
# Admin panel (create users)
# Only builtin admin or users with role 'admin' can access/create/delete users
# ----------------------
@app.route('/admin', methods=['GET','POST'])
def admin_panel():
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password')
        role = request.form.get('role') or 'admin'
        if not username or not password:
            flash('Username and password required')
            return redirect(url_for('admin_panel'))
        password_hash = generate_password_hash(password)
        try:
            db.execute('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)', (username, password_hash, role))
            db.commit()
            flash('User created')
        except sqlite3.IntegrityError:
            flash('Username already exists')
        return redirect(url_for('admin_panel'))

    users = db.execute('SELECT id, username, role FROM users ORDER BY username').fetchall()
    # pass ROLES so template can render the dropdown
    return render_template('admin.html', users=users, roles=ROLES)

@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User deleted')
    return redirect(url_for('admin_panel'))

# ----------------------
# Password management routes (ADDED)
# ----------------------
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Allows the currently logged-in DB user to change their own password.
    Built-in admin (username==ADMIN_USER) cannot change ADMIN_PASS here (it's code constant).
    """
    username = session.get('username')
    # prevent builtin admin from using this to change the code-based ADMIN_PASS
    if username == ADMIN_USER:
        flash('Built-in admin password is defined in code and cannot be changed via this interface. To change it, update ADMIN_PASS in your app configuration.')
        return redirect(url_for('index'))

    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    if not user:
        flash('User record not found')
        return redirect(url_for('index'))

    if request.method == 'POST':
        current = request.form.get('current_password') or ''
        newp = request.form.get('new_password') or ''
        confirm = request.form.get('confirm_password') or ''

        if not current or not newp or not confirm:
            flash('All fields are required')
            return redirect(url_for('change_password'))

        # verify current password
        if not check_password_hash(user['password_hash'], current):
            flash('Current password is incorrect')
            return redirect(url_for('change_password'))

        if newp != confirm:
            flash('New password and confirmation do not match')
            return redirect(url_for('change_password'))

        if len(newp) < 6:
            flash('New password should be at least 6 characters long')
            return redirect(url_for('change_password'))

        new_hash = generate_password_hash(newp)
        db.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_hash, username))
        db.commit()
        flash('Password changed successfully')
        return redirect(url_for('index'))

    return render_template('change_password.html', username=username)

@app.route('/admin/reset_password/<int:user_id>', methods=['GET', 'POST'])
def admin_reset_password(user_id):
    """
    Admin-only route to reset another user's password without needing their current password.
    Accessible to builtin admin and users with role 'admin'.
    """
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    if not user:
        flash('User not found')
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        newp = request.form.get('new_password') or ''
        confirm = request.form.get('confirm_password') or ''
        if not newp or not confirm:
            flash('Both password fields are required')
            return redirect(url_for('admin_reset_password', user_id=user_id))
        if newp != confirm:
            flash('Passwords do not match')
            return redirect(url_for('admin_reset_password', user_id=user_id))
        if len(newp) < 6:
            flash('New password should be at least 6 characters long')
            return redirect(url_for('admin_reset_password', user_id=user_id))

        new_hash = generate_password_hash(newp)
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
        db.commit()
        flash(f"Password for user '{user['username']}' has been reset")
        return redirect(url_for('admin_panel'))

    # GET
    return render_template('admin_reset_password.html', user=user)

# ----------------------
# Expenditure routes
# - Viewable by anyone
# - Only admin or expenditure role (or builtin admin) can POST (add)
# - Deleting is admin-only
# ----------------------
# ---------- Expenditure routes (updated) ----------
@app.route('/expenditure', methods=['GET','POST'])
def expenditure():
    db = get_db()

    # POST (create) -> restrict to admin/expenditure
    if request.method == 'POST':
        if not (is_builtin_admin() or session.get('role') in ('admin', 'expenditure')):
            flash('You do not have permission to add expenditures. Please log in with an account that has the necessary role.')
            return redirect(url_for('login'))

        month = request.form.get('month')  # database key like '2025-08'
        date = request.form.get('date') or None
        amount = request.form.get('amount') or '0'
        exp_type = request.form.get('type')
        reason = request.form.get('reason') or ''
        try:
            amount = int(amount)
        except Exception:
            flash('Invalid amount')
            return redirect(url_for('expenditure'))

        created_by = session.get('username') or 'unknown'
        db.execute('INSERT INTO expenditures (month, date, amount, type, reason, created_by) VALUES (?,?,?,?,?,?)',
                   (month, date, amount, exp_type, reason, created_by))
        db.commit()
        flash('Expenditure recorded')
        return redirect(url_for('expenditure'))

    # GET -> support optional month filter via query param ?month=YYYY-MM
    selected_month = request.args.get('month')  # e.g. '2025-08' or None for all
    if selected_month:
        cur = db.execute('SELECT * FROM expenditures WHERE month = ? ORDER BY date DESC, id DESC', (selected_month,))
    else:
        cur = db.execute('SELECT * FROM expenditures ORDER BY month DESC, date DESC, id DESC')
    exp_rows = cur.fetchall()

    # month options for filter / form
    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('expenditure.html',
                           expenditures=exp_rows,
                           months=month_options,
                           selected_month=selected_month)

@app.route('/expenditure/export')
def export_expenditures():
    """
    Export expenditures to CSV. Optional query param: ?month=YYYY-MM
    If month is provided, only that month's expenditures are exported; otherwise all.
    """
    db = get_db()
    month = request.args.get('month')
    if month:
        cur = db.execute('SELECT month, date, amount, type, reason, created_by FROM expenditures WHERE month = ? ORDER BY date DESC, id DESC', (month,))
        filename = f"expenditures_{month}.csv"
    else:
        cur = db.execute('SELECT month, date, amount, type, reason, created_by FROM expenditures ORDER BY month DESC, date DESC, id DESC')
        filename = "expenditures_all.csv"

    rows = cur.fetchall()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Month', 'Date', 'Amount', 'Type', 'Reason', 'Created By'])
    for r in rows:
        cw.writerow([
            r['month'],
            r['date'] if r['date'] else '',
            r['amount'] if r['amount'] is not None else '',
            r['type'] or '',
            r['reason'] or '',
            r['created_by'] or ''
        ])
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{filename}"'})

@app.route('/expenditure/delete/<int:exp_id>')
@require_roles('admin')
def delete_expenditure(exp_id):
    db = get_db()
    db.execute('DELETE FROM expenditures WHERE id = ?', (exp_id,))
    db.commit()
    flash('Expenditure deleted')
    return redirect(url_for('expenditure'))

# ----------------------
# Run
# ----------------------
if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print("Database not found. Run 'python init_db.py' to create it.")
    app.run(host="0.0.0.0", debug=True)
