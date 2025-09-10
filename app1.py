# app.py (updated)
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, Response
import sqlite3, os, io, csv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

APP_SECRET = 'change_this_secret'
# built-in admin credentials (also allowed to create accounts)
ADMIN_USER = 'admin'
ADMIN_PASS = 'admin'
DB_PATH = 'maintenance.db'

MONTHS = [
    ('aug_2025', '2025-08', 'August 2025'),
    ('sep_2025', '2025-09', 'September 2025'),
    ('oct_2025', '2025-10', 'October 2025'),
    ('nov_2025', '2025-11', 'November 2025'),
    ('dec_2025', '2025-12', 'December 2025')
]

TOTAL_HOUSES = 60

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

def admin_required():
    # allow either built-in admin or created users with role 'admin'/'editor'
    role = session.get('role')
    return role in ('admin', 'editor')

def only_admin_required():
    # route that only builtin admin or a user with role 'admin' can access
    return session.get('role') == 'admin'

@app.route('/')
def index():
    db = get_db()
    records = {}
    totals = {}
    expenditures_total = {}

    # Create a mapping of display keys to database keys
    month_mapping = {}
    for display_key, db_key, label in MONTHS:
        month_mapping[display_key] = db_key

        # fetch payments sum
        cur = db.execute('SELECT * FROM records WHERE month = ? ORDER BY house_number', (db_key,))
        rows = cur.fetchall()
        records[display_key] = rows

        tot_cur = db.execute('SELECT SUM(amount) as s FROM records WHERE month = ? AND amount IS NOT NULL', (db_key,))
        payments_sum = tot_cur.fetchone()['s'] or 0

        # fetch expenditures sum for this month
        exp_cur = db.execute('SELECT SUM(amount) as s FROM expenditures WHERE month = ?', (db_key,))
        exp_sum = exp_cur.fetchone()['s'] or 0
        expenditures_total[display_key] = int(exp_sum)

        # Net total = payments - expenditures
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
            session['role'] = user['role'] or 'editor'
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

@app.route('/add', methods=['GET','POST'])
def add():
    if not admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    if request.method == 'POST':
        house = int(request.form.get('house_number'))
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
def edit(rec_id):
    if not admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
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
def delete(rec_id):
    if not admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    db = get_db()
    db.execute('UPDATE records SET date_paid = NULL, amount = NULL WHERE id = ?', (rec_id,))
    db.commit()
    flash('Record cleared')
    return redirect(url_for('index'))

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
# ----------------------
@app.route('/admin', methods=['GET','POST'])
def admin_panel():
    # only builtin admin or user with role 'admin' can create accounts
    if not only_admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        role = request.form.get('role') or 'editor'
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
    return render_template('admin.html', users=users)

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
# Expenditure routes
# ----------------------
@app.route('/expenditure', methods=['GET','POST'])
def expenditure():
    if not admin_required():
        flash('Login required to add expenditure')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
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

    # list expenditures and provide form
    exp_rows = db.execute('SELECT * FROM expenditures ORDER BY month DESC, date DESC').fetchall()
    month_options = [(db_key, label) for _, db_key, label in MONTHS]
    return render_template('expenditure.html', expenditures=exp_rows, months=month_options)

@app.route('/expenditure/delete/<int:exp_id>')
def delete_expenditure(exp_id):
    if not admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
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
