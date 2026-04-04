#!/usr/bin/env python3
"""
Script de test pour vérifier le verrouillage brute force
Usage: python test_bruteforce.py
"""

import requests
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_brute_force():
    email = "directeur@xud-bank.com"  # Changez selon votre utilisateur de test
    wrong_password = "MauvaisPassword123"
    
    print(f"\n{'='*60}")
    print(f"TEST BRUTE FORCE - {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")
    print(f"Email: {email}")
    print(f"Tentatives: 5 échecs consécutifs\n")
    
    session = requests.Session()
    
    for i in range(1, 6):
        print(f"\n--- Tentative #{i} ---")
        
        response = session.post(
            f"{BASE_URL}/auth/login",
            data={"email": email, "password": wrong_password},
            allow_redirects=False
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 302:
            print("❌ ERREUR: Login réussi alors que mot de passe incorrect!")
            break
        elif response.status_code == 401:
            print("✅ Login refusé (401)")
            
            # Vérifier si compte verrouillé
            if "verrouillé" in response.text.lower():
                print("🔒 COMPTE VERROUILLÉ! Test réussi!")
                break
        else:
            print(f"⚠️ Status inattendu: {response.status_code}")
        
        # Petite pause entre tentatives
        time.sleep(1)
    
    print(f"\n{'='*60}")
    print("Test terminé. Vérifiez les logs pour plus de détails.")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    test_brute_force()
