import streamlit as st
import requests
from firebase_auth import FirebaseAuth
import os
from dotenv import load_dotenv
import google.generativeai as genai
import json
import firebase_admin
from firebase_admin import credentials, firestore
import re
import hashlib

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

load_dotenv()

# Firebase ve AI yapılandırması
auth_helper = FirebaseAuth()

FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_REST_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"

# Gemini AI yapılandırması
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# Firebase Admin SDK için - Sadece bir kez başlat
@st.cache_resource
def init_firebase():
    if not firebase_admin._apps:
        try:
            cred = credentials.Certificate("firebase-service-account.json")
            firebase_admin.initialize_app(cred)
        except Exception as e:
            st.error(f"Firebase başlatma hatası: {str(e)}")
            return None
    return firestore.client()

db = init_firebase()

st.set_page_config(page_title="AI Tarif Asistanı", page_icon="🍳", layout="centered")

# --- Yardımcı Fonksiyonlar ---
def login_with_email_password(email, password):
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    r = requests.post(FIREBASE_REST_URL, data=payload)
    if r.status_code == 200:
        return r.json()
    else:
        try:
            return r.json()
        except Exception:
            return None

def get_user_id_from_email(email):
    """Email'den user ID oluştur (basit hash)"""
    return hashlib.md5(email.encode()).hexdigest()

def save_favorite_recipe(user_email, recipe_data):
    """Tarifi favorilere kaydet"""
    if not db:
        st.error("Firebase bağlantısı yok!")
        return False
    
    try:
        user_id = get_user_id_from_email(user_email)
        doc_ref = db.collection('users').document(user_id).collection('favorites').document(recipe_data['id'])
        doc_ref.set(recipe_data)
        return True
    except Exception as e:
        st.error(f"Favorilere kaydetme hatası: {str(e)}")
        return False

def remove_favorite_recipe(user_email, recipe_id):
    """Tarifi favorilerden sil"""
    if not db:
        st.error("Firebase bağlantısı yok!")
        return False
    
    try:
        user_id = get_user_id_from_email(user_email)
        doc_ref = db.collection('users').document(user_id).collection('favorites').document(recipe_id)
        doc_ref.delete()
        return True
    except Exception as e:
        st.error(f"Favorilerden silme hatası: {str(e)}")
        return False

def get_favorite_recipes(user_email):
    """Kullanıcının favori tariflerini getir"""
    if not db:
        return []
    
    try:
        user_id = get_user_id_from_email(user_email)
        docs = db.collection('users').document(user_id).collection('favorites').get()
        favorites = []
        for doc in docs:
            recipe_data = doc.to_dict()
            favorites.append(recipe_data)
        return favorites
    except Exception as e:
        st.error(f"Favoriler getirme hatası: {str(e)}")
        return []

def is_recipe_favorite(user_email, recipe_id):
    """Tarifinın favoride olup olmadığını kontrol et"""
    if not db:
        return False
    
    try:
        user_id = get_user_id_from_email(user_email)
        doc = db.collection('users').document(user_id).collection('favorites').document(recipe_id).get()
        return doc.exists
    except Exception as e:
        return False

def generate_recipe_with_ai(ingredients):
    """Gemini (LangChain) ile tarif üret"""
    try:
        # Gemini modelini başlat
        llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",  # 2.5 yerine 1.5 daha hızlı
            #model="gemini-2.5-flash", 
            google_api_key=os.getenv("GEMINI_API_KEY"),
            temperature=0.3 # Yaratıcılık seviyesi düşürüldü (daha tutarlı JSON için)
            
        )
        
        # Prompt şablonu oluştur
        prompt = PromptTemplate(
            input_variables=["ingredients"],
            template="""
            Verilen malzemelerle yapılabilecek lezzetli tarifler öner. Malzemeler: {ingredients}
            
            Lütfen yanıtını tam olarak şu JSON formatında ver:
            ```json
            {{
                "recipes": [
                    {{
                        "id": "unique_recipe_id",
                        "name": "Tarif Adı",
                        "ingredients": ["malzeme1", "malzeme2", "malzeme3"],
                        "steps": ["adım1", "adım2", "adım3"],
                        "cook_time": "30 dakika",
                        "calories": 250,
                        "difficulty": "Kolay",
                        "description": "Kısa açıklama"
                    }}
                ]
            }}
            ```
            
            Önemli:
            - En az 3, en fazla 5 tarif öner
            - Her tarifin benzersiz bir ID'si olsun
            - Verilen malzemeleri mümkün olduğunca kullan
            - Adımları net ve anlaşılır yaz
            - Türkçe tarif isimleri kullan
            - Sadece ve kesinlikle bu JSON formatında yanıt ver, başka hiçbir metin, açıklama veya not ekleme. JSON nesnelerinin ve dizilerinin son elemanından sonra VİRGÜL BIRAKMA.
            """
        )
        
        # Zincir oluştur
        chain = LLMChain(llm=llm, prompt=prompt)
        
        # Tarifleri oluştur
        response_text = chain.run(ingredients=ingredients)
        
        # --- JSON'ı temizleme ve parse etme ---
        # Modelin bazen çıktıyı markdown bloğu içine alabileceğini varsayarak temizleme
        response_text = response_text.strip()
        # Bazı durumlarda model çıktıya 'json' kelimesini de ekleyebilir, onu da temizleyelim
        if response_text.startswith('```json'):
            response_text = response_text[7:].strip() # Baştaki 'json' ve boşlukları temizle
        if response_text.endswith('```'):
            response_text = response_text[:-3].strip() # Sondaki '```' ve boşlukları temizle
        
        # JSON hatalarını gidermeye yönelik basit bir deneme: Sonundaki fazla virgülü temizle
        response_text = re.sub(r',\s*\]', ']', response_text) # Array sonundaki fazla virgülü temizle
        response_text = re.sub(r',\s*\}', '}', response_text) # Object sonundaki fazla virgülü temizle

        # Debug için: AI'dan gelen ham yanıtı görmek isterseniz bu satırı açın
        # st.write(f"AI Ham Yanıtı: {response_text}") 
        
        recipes_data = json.loads(response_text)
        return recipes_data.get('recipes', [])
        
    except json.JSONDecodeError as e:
        st.error(f"AI yanıtı JSON hatası: {e}. AI'dan gelen yanıt beklenenden farklı olabilir.")
        st.error(f"Hatalı yanıtın başlangıcı: {response_text[:500]}...") # Hatalı yanıtın bir kısmını göster
        return []
    except Exception as e:
        st.error(f"AI tarif üretme hatası: {str(e)}")
        return []

def display_recipes(recipe_list, user_email, user_ingredients, show_favorites_buttons=True):
    """Tarifleri göster"""
    for recipe in recipe_list:
        with st.container():
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"### 🍽️ {recipe['name']}")
                st.markdown(f"**📝 Açıklama:** {recipe.get('description', 'Tarif açıklaması')}")
            
            with col2:
                st.markdown(f"**⏱️ Süre:** {recipe['cook_time']}")
                st.markdown(f"**🔥 Kalori:** {recipe['calories']} kcal")
                st.markdown(f"**📊 Zorluk:** {recipe['difficulty']}")
            
            # Malzemeler
            st.markdown("**🛒 Malzemeler:**")
            ingredients_text = " • ".join(recipe['ingredients'])
            st.markdown(f"• {ingredients_text}")
            
            # Eksik malzemeleri kontrol et ve göster
            if user_ingredients:
                recipe_ingredients = [ing.strip().lower() for ing in recipe['ingredients']]
                user_ingredients_clean = [ing.strip().lower() for ing in user_ingredients]
                missing_ingredients = []
                for recipe_ing in recipe_ingredients:
                    found = False
                    for user_ing in user_ingredients_clean:
                        if user_ing in recipe_ing or recipe_ing in user_ing:
                            found = True
                            break

                    if not found:
                        missing_ingredients.append(recipe_ing)
                
                if missing_ingredients:
                    st.warning(f"🛒 **Eksik Malzemeler:** {', '.join(missing_ingredients)}")
                else:
                    st.success("✅ **Tüm malzemeler mevcut!**")
            
            # Yapılışı
            st.markdown("**👩‍🍳 Yapılışı:**")
            for i, step in enumerate(recipe['steps'], 1):
                st.write(f"**{i}.** {step}")
            
            # Favori butonları
            if show_favorites_buttons:
                col_fav1, col_fav2 = st.columns(2)
                
                recipe_id = recipe.get('id', recipe['name'].lower().replace(' ', '_').replace('ç', 'c').replace('ğ', 'g').replace('ı', 'i').replace('ö', 'o').replace('ş', 's').replace('ü', 'u'))
                
                # Session state'te favori durumunu kontrol et
                fav_key = f"fav_{recipe_id}"
                
                with col_fav1:
                    # Favori durumunu kontrol et
                    is_fav = st.session_state.get(fav_key, is_recipe_favorite(user_email, recipe_id))
                    
                    if not is_fav:
                        if st.button(f"⭐ Favorilere Ekle", key=f"add_{recipe_id}_{hash(str(recipe))}"):
                            recipe_data = recipe.copy()
                            recipe_data['id'] = recipe_id
                            if save_favorite_recipe(user_email, recipe_data):
                                st.session_state[fav_key] = True
                                st.success(f"✅ {recipe['name']} favorilere eklendi!")
                               
                    else:
                        st.success("⭐ Favorilerde")
                
                with col_fav2:
                    is_fav = st.session_state.get(fav_key, is_recipe_favorite(user_email, recipe_id))
                    if is_fav:
                        if st.button(f"🗑️ Favorilerden Sil", key=f"remove_{recipe_id}_{hash(str(recipe))}"):
                            if remove_favorite_recipe(user_email, recipe_id):
                                st.session_state[fav_key] = False
                                st.success(f"🗑️ {recipe['name']} favorilerden silindi!")
                            
            
            st.markdown("---")

def get_user_display_name(user_email):
    """Kullanıcının adını getir"""
    try:
        # Firebase'den kullanıcı bilgilerini al
        from firebase_admin import auth as firebase_auth
        user_record = firebase_auth.get_user_by_email(user_email)
        if user_record.display_name:
            return user_record.display_name
        else:
            # Firestore'dan al
            user_id = get_user_id_from_email(user_email)
            if db:
                doc_ref = db.collection('users').document(user_id)
                doc = doc_ref.get()
                if doc.exists:
                    data = doc.to_dict()
                    return data.get('full_name', user_email.split('@')[0])
        return user_email.split('@')[0]
    except:
        return user_email.split('@')[0]

def show_dashboard(user_email):
    user_display_name = get_user_display_name(user_email)
    st.success(f"Hoş geldin, {user_display_name}!")
    
    # Tab menüsü
    tab1, tab2 = st.tabs(["🍳 Tarif Öner", "⭐ Favorilerim"])
    
    with tab1:
        st.header("🍳 Elindeki Malzemeleri Gir")
        
        # Session state'i başlat
        if 'current_recipes' not in st.session_state:
            st.session_state.current_recipes = []
        if 'current_ingredients' not in st.session_state:
            st.session_state.current_ingredients = []
        
        ingredients = st.text_input("Malzemeleri virgül ile ayırarak gir (ör: domates, yumurta, peynir)")

        if st.button("🤖 AI ile Tarif Öner", type="primary"):
            if ingredients.strip():
                with st.spinner("AI tarifleri oluşturuyor..."):
                    recipe_list = generate_recipe_with_ai(ingredients)
                    user_ingredients = [i.strip().lower() for i in ingredients.split(",") if i.strip()]
                    
                    # Session state'i güncelle
                    st.session_state.current_recipes = recipe_list
                    st.session_state.current_ingredients = user_ingredients
                    
                    # Favori durumlarını temizle (yeni tarifler için)
                    keys_to_remove = [key for key in st.session_state.keys() if key.startswith('fav_')]
                    for key in keys_to_remove:
                        del st.session_state[key]
            else:
                st.error("❌ Lütfen en az bir malzeme girin.")

        # Tarifleri göster
        if st.session_state.current_recipes:
            st.success(f"✨ {len(st.session_state.current_recipes)} farklı tarif önerisi:")
            display_recipes(st.session_state.current_recipes, user_email, st.session_state.current_ingredients)
        elif st.session_state.current_recipes == [] and ingredients.strip() and "AI ile Tarif Öner" in st.session_state: # Bu koşulu düzenledik
            st.warning("😔 Üzgünüm, bu malzemelerle uygun tarif bulamadım. Başka malzemeler deneyin.")

    with tab2:
        st.header("⭐ Favori Tariflerim")
        favorite_recipes = get_favorite_recipes(user_email)
        
        if favorite_recipes:
            st.info(f"📚 Toplam {len(favorite_recipes)} favori tarifiniz var")
            
            for recipe in favorite_recipes:
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"### 🍽️ {recipe['name']}")
                        if 'description' in recipe:
                            st.markdown(f"**📝 Açıklama:** {recipe['description']}")
                    
                    with col2:
                        st.markdown(f"**⏱️ Süre:** {recipe['cook_time']}")
                        st.markdown(f"**🔥 Kalori:** {recipe['calories']} kcal")
                        if 'difficulty' in recipe:
                            st.markdown(f"**📊 Zorluk:** {recipe['difficulty']}")
                    
                    # Malzemeler
                    if 'ingredients' in recipe:
                        st.markdown("**🛒 Malzemeler:**")
                        ingredients_text = " • ".join(recipe['ingredients'])
                        st.markdown(f"• {ingredients_text}")
                    
                    # Yapılışı
                    if 'steps' in recipe:
                        with st.expander("👩‍🍳 Yapılışını Göster"):
                            for i, step in enumerate(recipe['steps'], 1):
                                st.write(f"**{i}.** {step}")
                    
                    # Favorilerden sil butonu
                    recipe_id = recipe.get('id', recipe['name'].lower().replace(' ', '_'))
                    if st.button(f"🗑️ Favorilerden Sil", key=f"fav_remove_{recipe_id}"):
                        if remove_favorite_recipe(user_email, recipe_id):
                            st.success(f"🗑️ {recipe['name']} favorilerden silindi!")
                            st.rerun()
                    
                    st.markdown("---")
        else:
            st.info("📭 Henüz favori tarifiniz yok. Tarif öner sekmesinden tarifler oluşturun ve favorilerinize ekleyin!")

    st.markdown("---")
    if st.button("🚪 Çıkış yap"):
        # Session state'i temizle
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

def password_strength_feedback(password):
    valid, msg = auth_helper.check_password_strength(password)
    if not valid:
        st.warning(msg)
    else:
        st.success(msg)
    return valid

# --- Ana Akış ---
if "user" not in st.session_state:
    st.session_state.user = None

if st.session_state.user:
    show_dashboard(st.session_state.user)
else:
    # Sidebar menü sadece giriş yapmamış kullanıcılar için
    menu = ["🔑 Giriş Yap", "📧 Kayıt Ol", "🔄 Şifre Sıfırla"]
    choice = st.sidebar.selectbox("Menü", menu)
    
    if choice == "🔑 Giriş Yap":
        st.title("🔑 Giriş Yap")
        email = st.text_input("📧 E-posta")
        password = st.text_input("🔒 Şifre", type="password")
        
        if st.button("🔑 Giriş Yap", type="primary"):
            if email and password:
                with st.spinner("Giriş yapılıyor..."):
                    result = login_with_email_password(email, password)
                    if result and isinstance(result, dict) and result.get('idToken'):
                        st.session_state.user = email
                        st.success("✅ Başarıyla giriş yapıldı!")
                        st.rerun()
                    else:
                        error_message = "❌ E-posta veya şifre hatalı!"
                        if result and isinstance(result, dict):
                            error = result.get('error', {})
                            message = error.get('message', "")
                            if message == "EMAIL_NOT_FOUND":
                                error_message = "👤 Böyle bir kullanıcı yok, hesabınız yoksa kayıt olun."
                        st.error(error_message)
            else:
                st.error("❌ Lütfen tüm alanları doldurun.")
                
    elif choice == "📧 Kayıt Ol":
        st.title("📧 Yeni Hesap Oluştur")
        
        # Ad ve Soyad alanları
        col1, col2 = st.columns(2)
        with col1:
            first_name = st.text_input("👤 Adınız *", placeholder="Adınızı girin")
        with col2:
            last_name = st.text_input("👤 Soyadınız *", placeholder="Soyadınızı girin")
        
        email = st.text_input("📧 E-posta *", placeholder="ornek@email.com")
        password = st.text_input("🔒 Şifre *", type="password", placeholder="Güçlü bir şifre oluşturun")
        password2 = st.text_input("🔒 Şifre (tekrar) *", type="password", placeholder="Şifrenizi tekrar girin")
        
        if password:
            password_strength_feedback(password)
            
        if st.button("📧 Kayıt Ol", type="primary"):
            # Form validasyonu
            errors = []
            
            # Ad kontrolü
            if not first_name.strip():
                errors.append("Ad alanı boş bırakılamaz")
            else:
                is_valid, msg = auth_helper.validate_name(first_name)
                if not is_valid:
                    errors.append(f"Ad: {msg}")
            
            # Soyad kontrolü
            if not last_name.strip():
                errors.append("Soyad alanı boş bırakılamaz")
            else:
                is_valid, msg = auth_helper.validate_name(last_name)
                if not is_valid:
                    errors.append(f"Soyad: {msg}")
            
            # Diğer kontroller
            if not email.strip():
                errors.append("E-posta alanı boş bırakılamaz")
            if not password:
                errors.append("Şifre alanı boş bırakılamaz")
            elif password != password2:
                errors.append("Şifreler eşleşmiyor")
            else:
                valid, msg = auth_helper.check_password_strength(password)
                if not valid:
                    errors.append(msg)
            
            if errors:
                st.error("❌ Lütfen aşağıdaki hataları düzeltin:")
                for error in errors:
                    st.write(f"• {error}")
            else:
                with st.spinner("Hesap oluşturuluyor..."):
                    result = auth_helper.register_user(
                        email.strip(), 
                        password, 
                        first_name.strip(), 
                        last_name.strip()
                    )
                    
                    if hasattr(result, 'uid'):
                        st.success("✅ Kayıt başarılı! Giriş yapabilirsiniz.")
                        st.info(f"👤 Hoş geldin, {first_name.title()} {last_name.title()}!")
                        st.balloons()
                    else:
                        error_msg = str(result)
                        if "EMAIL_EXISTS" in error_msg:
                            st.error("❌ Bu e-posta ile zaten bir hesap var, lütfen giriş yapın.")
                        else:
                            st.error(f"❌ Kayıt başarısız: {result}")
                
    elif choice == "🔄 Şifre Sıfırla":
        st.title("🔄 Şifre Sıfırlama")
        email = st.text_input("📧 E-posta")
        
        if st.button("📧 Şifre Sıfırlama Linki Gönder", type="primary"):
            if email:
                with st.spinner("Link gönderiliyor..."):
                    link = auth_helper.send_password_reset(email)
                    if link and link.startswith("http"):
                        st.success("✅ Şifre sıfırlama linki e-posta adresinize gönderildi.")
                        st.write(f"🔗 Link: {link}")
                    else:
                        st.error(f"❌ Hata: {link}")
            else:
                st.error("❌ Lütfen e-posta adresinizi girin.")

# Sidebar'da bilgi
st.sidebar.markdown("---")
st.sidebar.markdown("🤖 **AI Tarif Asistanı**")
st.sidebar.markdown("Gemini 2.5 Flash ile güçlendirilmiştir")