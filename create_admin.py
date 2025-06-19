from app import db, User, app
from werkzeug.security import generate_password_hash

with app.app_context():
    db.session.rollback()
    existing_admin = User.query.filter_by(username='admin').first()
    print(f'Existing admin: {existing_admin}')
    if not existing_admin:
        new_admin = User(username='admin', 
                        password_hash=generate_password_hash('admin123'), 
                        is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        print('Created new admin user')
    else:
        print('Admin user already exists')
