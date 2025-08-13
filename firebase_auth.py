import os
import firebase_admin
from firebase_admin import credentials, auth
from dotenv import load_dotenv

load_dotenv()

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "serviceAccountKey.json"

class FirebaseAuth:
    def __init__(self):
        self.firebase_config = {
            "apiKey": os.getenv("FIREBASE_API_KEY"),
            "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
            "projectId": os.getenv("FIREBASE_PROJECT_ID"),
            "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
            "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
            "appId": os.getenv("FIREBASE_APP_ID")
        }
        if not firebase_admin._apps:
            cred = credentials.Certificate("serviceAccountKey.json")
            firebase_admin.initialize_app(cred)
        try:
            from google.cloud import firestore
            self.db = firestore.Client()
        except Exception as e:
            self.db = None
            print(f"Firestore başlatılamadı: {e}")

    def save_user_to_firestore(self, user, first_name=None, last_name=None):
        if not self.db:
            print("Firestore bağlantısı yok!")
            return False
        try:
            from google.cloud import firestore
            doc_ref = self.db.collection("users").document(user.uid)
            
            user_data = {
                "email": user.email,
                "uid": user.uid,
                "created_at": firestore.SERVER_TIMESTAMP
            }
            
            # Ad ve soyad bilgilerini ekle
            if first_name:
                user_data["first_name"] = first_name.strip().title()
            if last_name:
                user_data["last_name"] = last_name.strip().title()
            if first_name and last_name:
                user_data["full_name"] = f"{first_name.strip().title()} {last_name.strip().title()}"
            
            doc_ref.set(user_data)
            return True
        except Exception as e:
            print(f"Firestore'a kaydedilemedi: {e}")
            return str(e)

    def register_user(self, email, password, first_name=None, last_name=None):
        try:
            # Firebase Authentication kullanıcı oluştur
            user_data = {
                "email": email,
                "password": password
            }
            
            # Display name olarak ad soyad ekle
            if first_name and last_name:
                user_data["display_name"] = f"{first_name.strip().title()} {last_name.strip().title()}"
            elif first_name:
                user_data["display_name"] = first_name.strip().title()
            
            user = auth.create_user(**user_data)
            
            # Firestore'a kullanıcı bilgilerini kaydet
            save_result = self.save_user_to_firestore(user, first_name, last_name)
            
            if save_result is True:
                return user
            else:
                # Firestore'a kayıt başarısız olursa Authentication'dan kullanıcıyı sil
                try:
                    auth.delete_user(user.uid)
                    return f"Veritabanı kayıt hatası: {save_result}"
                except:
                    return f"Kayıt hatası: {save_result}"
                    
        except Exception as e:
            return str(e)

    def validate_name(self, name):
        """Ad ve soyad validasyonu"""
        import re
        if not name or len(name.strip()) < 2:
            return False, "Ad/Soyad en az 2 karakter olmalı."
        if not re.match(r'^[a-zA-ZçğıöşüÇĞIİÖŞÜ\s-]+$', name.strip()):
            return False, "Ad/Soyad sadece harf, boşluk ve tire içerebilir."
        return True, "Geçerli isim."

    def get_user_profile(self, uid):
        """Kullanıcı profil bilgilerini getir"""
        if not self.db:
            return None
        try:
            doc_ref = self.db.collection("users").document(uid)
            doc = doc_ref.get()
            if doc.exists:
                return doc.to_dict()
            return None
        except Exception as e:
            print(f"Kullanıcı profili getirilemedi: {e}")
            return None

    def update_user_profile(self, uid, first_name=None, last_name=None):
        """Kullanıcı profil bilgilerini güncelle"""
        if not self.db:
            return False, "Firestore bağlantısı yok!"
        
        try:
            doc_ref = self.db.collection("users").document(uid)
            update_data = {}
            
            if first_name:
                update_data["first_name"] = first_name.strip().title()
            if last_name:
                update_data["last_name"] = last_name.strip().title()
            if first_name and last_name:
                update_data["full_name"] = f"{first_name.strip().title()} {last_name.strip().title()}"
                # Authentication display name'i de güncelle
                auth.update_user(uid, display_name=f"{first_name.strip().title()} {last_name.strip().title()}")
            
            if update_data:
                from google.cloud import firestore
                update_data["updated_at"] = firestore.SERVER_TIMESTAMP
                doc_ref.update(update_data)
                return True, "Profil güncellendi."
            else:
                return False, "Güncellenecek bilgi bulunamadı."
                
        except Exception as e:
            return False, str(e)

    def login_user(self, email, password):
        # Firebase Admin SDK doğrudan login işlemi yapmaz, sadece kullanıcı yönetimi sağlar.
        # Giriş için REST API kullanılmalı. (Streamlit tarafında yapılacak)
        pass

    def send_password_reset(self, email):
        try:
            link = auth.generate_password_reset_link(email)
            return link
        except Exception as e:
            return str(e)

    def check_password_strength(self, password):
        import re
        if len(password) < 8:
            return False, "Şifre en az 8 karakter olmalı."
        if not re.search(r"[A-Z]", password):
            return False, "Şifre en az bir büyük harf içermeli."
        if not re.search(r"[a-z]", password):
            return False, "Şifre en az bir küçük harf içermeli."
        if not re.search(r"[0-9]", password):
            return False, "Şifre en az bir rakam içermeli."
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
            return False, "Şifre en az bir özel karakter içermeli."
        return True, "Güçlü şifre."