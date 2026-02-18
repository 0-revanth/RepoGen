from main import app, db

with app.app_context():
    db.create_all()
    print('Database created successfully with all tables and columns!')
