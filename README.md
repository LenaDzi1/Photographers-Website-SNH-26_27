# Photographers

Photographers is a PHP and MySQL photo gallery with Standard and Premium accounts. Members can upload photos, browse the gallery, and download photos their account can access. Administrators manage accounts and Premium requests.

## Run locally

Install PHP 8.1 or later with the `pdo_mysql` and `gd` extensions, and MySQL 8 with its command-line client. Run the commands from the repository root.

1. Start MySQL and initialize a fresh local database.

   ```sh
   mysql --user=root --password --execute="SOURCE schema.sql"
   ```

   Connect to MySQL as an administrator again. Create a local application user, replacing `replace-with-your-local-db-password` with a password of your choice.

   ```sql
   CREATE USER 'photographers'@'127.0.0.1' IDENTIFIED BY 'replace-with-your-local-db-password';
   GRANT SELECT, INSERT, UPDATE, DELETE ON photographers.* TO 'photographers'@'127.0.0.1';
   ```

2. Set the connection details in the shell from which you will run PHP. Use the database user's password from step 1.

   **PowerShell**

   ```powershell
   $env:DB_DSN = 'mysql:host=127.0.0.1;dbname=photographers;charset=utf8mb4'
   $env:DB_USER = 'photographers'
   $env:DB_PASSWORD = 'replace-with-your-local-db-password'
   ```

   **Bash or Zsh**

   ```sh
   export DB_DSN='mysql:host=127.0.0.1;dbname=photographers;charset=utf8mb4'
   export DB_USER='photographers'
   export DB_PASSWORD='replace-with-your-local-db-password'
   ```

3. Optionally load the demo accounts and bundled photos, then start the development server. The document root is `public/`.

   ```sh
   php seed-demo.php --with-photos
   php -d upload_max_filesize=4M -d post_max_size=8M -S 127.0.0.1:8000 -t public
   ```

   Open [the local gallery](http://127.0.0.1:8000).

## Demo accounts and photos

Use the seed script with a local or test database. It prints each account's initial password when it creates the account.

| Username | Role | Initial password |
| --- | --- | --- |
| `admin` | Administrator | `Admin2026!@#` |
| `alice` | Premium | `AlicePassword2026!` |
| `bob` | Standard | `BobPassword2026!` |

| Repository file | Gallery description | Owner | Gallery access |
| --- | --- | --- | --- |
| [nice-cat.jpg](demo/photos/nice-cat.jpg) | `nice cat` | `admin` | All signed-in members |
| [standard-cat.jpg](demo/photos/standard-cat.jpg) | `standard cat` | `bob` | All signed-in members |
| [premium-cat.jpg](demo/photos/premium-cat.jpg) | `premium cat` | `alice` | Premium members and administrators |

Run `php seed-demo.php` to create only the accounts. To use your own images, run `php seed-demo.php nice.jpg standard.jpg premium.jpg` with the three paths in the order shown above. Re-running the seed keeps existing demo passwords and skips identical imports.

The demo JPEGs live in `demo/photos/` and can be added to Git like any other file. Anyone with access to the repository can view these JPEGs, including the Premium example. The Premium restriction applies to the copy served by the application.

## How the site works

- **Accounts.** Members can register, sign in, and change their passwords. The app accepts passwords of 12–72 bytes and stores bcrypt hashes.
- **Gallery.** Sign in as Bob to see the two Standard photos and a locked Premium entry. Alice and the administrator can open and download all three photos.
- **Premium requests.** Bob can request Premium from his account or a locked gallery entry. An administrator can approve or decline the request, change a member's access, revoke their sessions, or delete their account and photos under **Manage users**.
- **Uploads.** Signed-in members can upload JPEG, PNG, or BMP files up to 4 MiB and 25 megapixels. Premium members and administrators can mark uploads as Premium. The upload form supports original, portrait, and landscape framing. Images above 8 megapixels are resized before saving.
- **Password recovery.** The local app writes reset messages to `outbox/` in the repository root. Use the link in the generated message within 30 minutes. Set `APP_URL` to your local base URL if it differs from `http://127.0.0.1:8000`.

## How photo storage works

The seed script reads the JPEG files from the repository and uses the same image processing as the upload form. PHP checks the image format and dimensions, decodes the image with GD, and re-encodes it. MySQL stores the resulting bytes in `photos.image` as a `MEDIUMBLOB`, with the MIME type, description, owner, and Premium flag in the same row. The gallery reads the stored bytes and sends them with the corresponding content type after checking the member's access.
