import { Injectable } from '@angular/core';
import { User, updatePassword as firebaseUpdatePassword, sendEmailVerification } from 'firebase/auth'; // Importe os métodos necessários
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import {
  Auth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  authState,
  GoogleAuthProvider,
  signInWithRedirect,
  getRedirectResult,
  sendPasswordResetEmail,
} from '@angular/fire/auth';
import { Firestore, doc, setDoc } from '@angular/fire/firestore';

interface Credentials {
  email: string;
  password: string;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  constructor(private auth: Auth, private firestore: Firestore) {}

  async register(credentials: Credentials): Promise<User | null> {
    try {
      const userCredential = await createUserWithEmailAndPassword(
        this.auth,
        credentials.email,
        credentials.password
      );
      const user = userCredential.user;
  
      const userDoc = doc(this.firestore, `users/${user.uid}`);
      await setDoc(userDoc, {
        email: user.email,
        imageUrl: null,
        createdAt: new Date(),
      });
  
      // Enviar e-mail de verificação
      await sendEmailVerification(user);
  
      // Retornar o usuário, mas não redirecionar ainda
      return user;
    } catch (e) {
      console.error('Error during registration:', e);
      return null;
    }
  }
  
  
  

  async changePassword(newPassword: string): Promise<void> {
    const user = this.auth.currentUser;
    if (user) {
      await firebaseUpdatePassword(user, newPassword);
    } else {
      throw new Error('Usuário não autenticado');
    }
  }

  async sendPasswordResetEmail(email: string): Promise<void> {
    try {
      await sendPasswordResetEmail(this.auth, email);
    } catch (error) {
      console.error('Erro ao enviar e-mail de redefinição de senha:', error);
      throw error;
    }
  }

  getUser(): Observable<User | null> {
    return authState(this.auth);
  }

  getUserId(): string | null {
    const user = this.auth.currentUser; // Usar currentUser para obter o ID do usuário logado
    return user ? user.uid : null;
  }
  

  async loginWithGoogle(): Promise<void> {
    try {
      const provider = new GoogleAuthProvider();
      await signInWithRedirect(this.auth, provider);
    } catch (e) {
      console.error('Erro ao fazer login com Google:', e);
    }
  }

  async login(credentials: Credentials): Promise<User | null> {
    try {
      const userCredential = await signInWithEmailAndPassword(
        this.auth,
        credentials.email,
        credentials.password
      );
  
      const user = userCredential.user;
  
      if (!user.emailVerified) {
        await this.logout(); // Desconectar se o e-mail não estiver verificado
        throw new Error('Por favor, verifique seu e-mail antes de fazer login.');
      }
  
      return user;
    } catch (e) {
      console.error('Erro ao fazer login:', e);
      return null;
    }
  }
  
  

  async logout(): Promise<void> {
    try {
      await signOut(this.auth);
    } catch (e) {
      console.error('Erro ao fazer logout:', e);
    }
  }

  async handleRedirectResult(): Promise<User | null> {
    try {
      const result = await getRedirectResult(this.auth);
      return result?.user || null;
    } catch (e) {
      console.error('Erro ao recuperar o resultado do redirecionamento:', e);
      return null;
    }
  }
}
