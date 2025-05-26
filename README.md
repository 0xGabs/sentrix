# Sentrix

*Hecho por 0xGabs*

Sentrix es una herramienta de línea de comandos para **escaneo** y **monitoreo en tiempo real** de archivos, buscando patrones sensibles (contraseñas, secretos, configuraciones, etc.) definidos por el usuario.

---

## Características

* **Escaneo estático** de archivos por extensiones y nombres sensibles.
* **Monitoreo en tiempo real** de directorios para detectar modificaciones y volver a escanear automáticamente.
* **Salida enriquecida** con tablas de `rich` para visualizar hallazgos.
* **Configuración flexible** mediante archivos YAML de patrones.
* **CLI intuitiva** con flags para personalizar comportamiento:

  * `--patterns` (obligatorio) para indicar archivos YAML de patrones.
  * `--watch` para activar vigilancia continua.
  * `--version` para mostrar versión.
  * `--verbose` para logs detallados.

---

## Instalación

1. Clona este repositorio:

   ```bash
   git clone https://github.com/0xGabs/sentrix.git
   cd sentrix
   ```
2. Crea y activa un entorno virtual (recomendado):

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .\.venv\Scripts\activate   # Windows (Si te arroja error intenta esto primero: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process)
   ```
3. Instala en modo editable:

   ```bash
   pip install -e .
   ```

> En el futuro, tras publicar en PyPI, podrás usar `pip install sentrix`.

---

## Uso básico

Sentrix puede ejecutarse desde la terminal para escanear archivos específicos o para vigilar cambios en tiempo real.

### 1. Escaneo puntual

```bash
sentrix ./mi_app --patterns patrones.yaml
```

* Escanea todos los archivos dentro de `./mi_app` (de forma recursiva).
* Usa el archivo `patrones.yaml` como referencia para buscar expresiones sensibles.
* La salida muestra los hallazgos en una tabla con los siguientes campos:

  * **Archivo**: Ruta donde se encontró el match.
  * **Línea**: Línea dentro del archivo.
  * **Severidad**: Nivel definido por el patrón.
  * **Mensaje**: Explicación de lo detectado.

También puedes escanear archivos sueltos:

```bash
sentrix ./archivo.py --patterns patrones.yaml
```

O múltiples rutas al mismo tiempo:

```bash
sentrix ./src ./tests ./api.py --patterns patrones.yaml
```

### 2. Monitoreo en tiempo real

```bash
sentrix ./src --patterns patrones.yaml --watch
```

* Mantiene vigilancia continua sobre `./src`.
* Cuando un archivo cambia, se vuelve a cargar `patrones.yaml` y se escanea automáticamente el archivo afectado.
* Ideal para desarrollo activo o entornos donde se generan archivos sensibles dinámicamente.

> Puedes presionar `Ctrl + C` para detener el monitoreo.

### Flags adicionales

* `--verbose`  : Muestra logs de depuración.

* `--version`  : Muestra la versión instalada.

---

## Formato de patrones (YAML)

Cada archivo `patterns.yaml` debe tener la siguiente estructura:

```yaml
patterns:
  - name: Google API Key
    regex: "AIza[0-9A-Za-z\\-_]{35}"
    severity: high
    message: "Google API key found"
    tags: [cloud, google]

```
* **`name`**: Nombre descriptivo del patrón que será mostrado en los hallazgos.
* **`regex`**: Expresión regular a buscar.
* **`severity`**: Nivel de severidad (`critical`, `high`, `medium`, `low`).
* **`message`**: Descripción breve del hallazgo.
* **`tags`**: Lista opcional de etiquetas para clasificar el hallazgo (como cloud, google, api, etc).

---

5. **Control de versiones y commits**:

   * Sigue [Conventional Commits](https://www.conventionalcommits.org/) para mensajes claros.
   * Configura un gancho pre-commit (`pre-commit`) para automatizar checks antes de cada commit.

6. **Colaboración**:

   * Abre un *issue* para discutir cambios mayores.
   * Envía un *pull request* con una descripción clara del cambio y referencia al issue.
