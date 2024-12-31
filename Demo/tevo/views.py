# views.py
import jwt
from django.shortcuts import render, redirect
from django.conf import settings
from services.api.client import APIClient
import requests

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not email or not password:
            return render(request, 'login.html', 
                        {'error': 'Correo electrónico y contraseña son obligatorios'})

        try:
            result = APIClient.login(email, password)

            if result.get("msg"):
                return render(request, 'login.html', {'error': result["msg"]})

            token = result.get('access_token')
            if not token:
                return render(request, 'login.html', {'error': 'No fue posible iniciar sesión. Intente más tarde.'})

            try:
                unverified = jwt.decode(token, options={"verify_signature": False})
                
                # Obtener el rol desde la estructura correcta del token
                user_data = unverified.get('sub', {})
                if isinstance(user_data, dict):
                    user_role = user_data.get('rol')
                else:
                    user_role = None

                # Guardar en sesión
                request.session['user_token'] = token
                request.session['user_role'] = user_role
                
                # Redirigir a diferentes templates según el rol
                if user_role == 'creador':
                    return render(request, 'creador_home.html')
                elif user_role == 'participante':
                    return render(request, 'participante_home.html')
                else:
                    # Template por defecto o manejo de rol desconocido
                    return render(request, 'login.html')
                
            except Exception as e:
                print(f"Error al iniciar sesión: {str(e)}")
                return render(request, 'login.html', 
                            {'error': 'Error procesando el inicio de sesión'})
                
        except requests.exceptions.RequestException as e:
            print(f"Error de request: {str(e)}")
            return render(request, 'login.html', 
                        {'error': 'Error al conectar con el servidor'})

    return render(request, 'login.html')


def crear_cuenta_view(request):
    if request.method == 'POST':
        nombre = request.POST.get('nombre')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')

        # Validaciones básicas
        if not all([nombre, email, password, confirm_password]):
            return render(request, 'crear_cuenta.html', 
                        {'error': 'Todos los campos son obligatorios'})

        if password != confirm_password:
            return render(request, 'crear_cuenta.html', 
                        {'error': 'Las contraseñas no coinciden'})

        # Validación básica de formato de email
        if '@' not in email or '.' not in email:
            return render(request, 'crear_cuenta.html', 
                        {'error': 'Por favor ingrese un correo electrónico válido'})

        try:
            # Asumiendo que APIClient tiene un método register similar al login
            print(nombre, email, password)
            result = APIClient.registro(nombre, email, password)

            if result.get("msg"):
                return render(request, 'crear_cuenta.html', {'error': result["msg"]})

            # Si el registro fue exitoso, iniciar sesión automáticamente
            try:
                login_result = APIClient.login(email, password)
                token = login_result.get('access_token')

                if not token:
                    return render(request, 'login.html', 
                                {'error': 'Cuenta creada exitosamente. Por favor inicie sesión.'})

                # Decodificar el token para obtener información del usuario
                unverified = jwt.decode(token, options={"verify_signature": False})
                
                # Obtener el rol desde la estructura del token
                user_data = unverified.get('sub', {})
                if isinstance(user_data, dict):
                    user_role = user_data.get('rol')
                else:
                    user_role = None

                # Guardar en sesión
                request.session['user_token'] = token
                request.session['user_role'] = user_role
                
                # Redirigir según el rol
                if user_role == 'creador':
                    return render(request, 'creador_home.html')
                elif user_role == 'participante':
                    return render(request, 'participante_home.html')
                else:
                    # Template por defecto
                    return render(request, 'participante_home.html')

            except Exception as e:
                print(f"Error al iniciar sesión después del registro: {str(e)}")
                return render(request, 'login.html', 
                            {'error': 'Cuenta creada exitosamente. Por favor inicie sesión.'})

        except requests.exceptions.RequestException as e:
            print(f"Error de request: {str(e)}")
            return render(request, 'crear_cuenta.html', 
                        {'error': 'Error al conectar con el servidor'})

    return render(request, 'crear_cuenta.html')

def logout_view(request):
    # Limpiar las variables de sesión
    request.session.pop('user_token', None)
    request.session.pop('user_role', None)
    request.session.flush()  # Limpia toda la sesión
    
    # Redirigir al login
    return redirect('login')



# Opcional: Decorator para proteger vistas según rol
from functools import wraps
from django.http import HttpResponseForbidden

# Ítalo: esta función la podemos utilizar para cuando queremos proteger una vista en base al rol.
# ver el ejemplo de la función de más abajo 'role_required'
def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user_role = request.session.get('user_role')
            if user_role not in allowed_roles:
                return HttpResponseForbidden("No tienes permiso para acceder a esta página")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# Ejemplo de uso del decorator
@role_required(['creador'])
def admin_only_view(request):
    return render(request, 'creador_home.html')

def crea_encuesta(request):
    if request.method == 'POST':
        form = crea_encuesta(request.POST)
        if form.is_valid():
            # Obtener datos del formulario
            title = form.cleaned_data['title']
            description = form.cleaned_data['description']
            start_date = form.cleaned_data['start_date']
            end_date = form.cleaned_data['end_date']
            options = request.POST.getlist('options[]')

            # Validaciones
            errors = []
            
            # Validar que todos los campos estén presentes
            if not all([title, description, start_date, end_date, options]):
                errors.append("Todos los campos son obligatorios")

            # Validar fechas
            now = timezone.now()
            if start_date < now:
                errors.append("La fecha de inicio debe ser mayor o igual a la fecha actual")
            
            if end_date <= start_date:
                errors.append("La fecha de fin debe ser mayor a la fecha de inicio")

            # Validar opciones de respuesta
            valid_options = [opt for opt in options if opt.strip()]
            if len(valid_options) < 2:
                errors.append("Debe existir al menos dos opciones de respuesta")

            # Validar título único
            if crea_encuesta.objects.filter(title=title).exists():
                errors.append("Ya existe una encuesta con este título")

            if errors:
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)

            try:
                # Crear la encuesta
                survey = Survey.objects.create(
                    title=title,
                    description=description,
                    start_date=start_date,
                    end_date=end_date,
                    created_by=request.user
                )

                # Crear las opciones de respuesta
                for option_text in valid_options:
                    SurveyOption.objects.create(
                        survey=survey,
                        text=option_text
                    )

                messages.success(request, "Encuesta creada exitosamente")
                return JsonResponse({
                    'success': True,
                    'redirect_url': f'/survey/{survey.id}/'
                })

            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'errors': ["Error al crear la encuesta. Por favor, intente nuevamente."]
                }, status=500)

    return render(request, 'crear_encuesta.html')