import os
import zipfile


def build_ipa(bundle_dir: str, output_path: str):
    app_dir_name = os.path.basename(bundle_dir)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(bundle_dir):
            for name in files:
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, bundle_dir)
                arcname = os.path.join("Payload", app_dir_name, rel_path)
                zipf.write(full_path, arcname)
