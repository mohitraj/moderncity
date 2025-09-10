from flask import Flask, g, render_template, request, redirect, url_for, session, flash
import sqlite3, os, io, csv

APP_SECRET = 'change_this_secret'
ADMIN_USER = 'admin'
ADMIN_PASS = 'adminpass@123'
DB_PATH = 'maintenance.db'

# Changed to use CSS-friendly keys while keeping database values intact
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
    return session.get('admin') == True

@app.route('/')
def index():
    try:
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
    except Exception as e:
        # Show error on page so you can see what's failing
        import traceback
        tb = traceback.format_exc()
        return f"<h3>Index rendering failed — server error</h3><pre>{tb}</pre>", 500

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u == ADMIN_USER and p == ADMIN_PASS:
            session['admin'] = True
            flash('Signed in as admin')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin', None)
    flash('Logged out')
    return redirect(url_for('index'))

@app.route('/add', methods=['GET','POST'])
def add():
    if not admin_required():
        flash('Admin access required')
        return redirect(url_for('login'))
    if request.method == 'POST':
        house = int(request.form.get('house_number'))
        month = request.form.get('month')  # This will be the database key now
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
    
    # Pass database keys for form options
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
    
    # Pass database keys for form options
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
    # Convert display key back to database key
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
    from flask import Response
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
    from flask import Response
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{filename}"'})

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print("Database not found. Run 'python init_db.py' to create it.")
    app.run(host="0.0.0.0")
