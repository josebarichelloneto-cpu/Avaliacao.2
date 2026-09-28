# 07 — Testes de falha

Registro dos 6 casos exigidos na etapa 16, executados na implantação de produção `https://avaliacao-2-ev8.pages.dev`. Todos os valores sensíveis (cookies, state, code, tokens) foram substituídos por `[REMOVIDO]`.

---

## Caso 1: retorno sem cookie temporário

**Preparação:** login iniciado com `/oauth/login/google` em uma janela comum; interrompido na tela de autenticação do Google, antes de fornecer as credenciais.

**Pedido enviado:** URL de autorização copiada da primeira janela e aberta em uma janela privativa, que não possuía o cookie `__Host-oauth-tx` gerado na primeira janela. Login concluído nessa segunda janela.

**Resultado esperado:** a rota de retorno recusa a resposta por ausência do cookie de transação e não cria sessão.

**Resultado observado:** a rota `/oauth/callback/google` respondeu com status 400 e a mensagem "Cookie de transação ausente". Nenhuma sessão foi criada; o site permaneceu exibindo "Nenhuma sessão neste navegador." após o redirecionamento.

---

## Caso 2: state alterado

**Preparação:** login iniciado com `/oauth/login/google`; interrompido na tela de autenticação do Google, antes de fornecer as credenciais.

**Pedido enviado:** um único caractere do parâmetro `state` foi alterado diretamente na barra de endereço antes de prosseguir com o login. URL modificada não registrada, conforme instrução do laboratório.

**Resultado esperado:** a rota de retorno recusa a resposta antes de trocar o código, por divergência entre o resumo do `state` recebido e o resumo salvo no D1.

**Resultado observado:** a rota `/oauth/callback/google` respondeu com status 400 e a mensagem "Parâmetro state inválido". A troca do código com o Google não foi realizada; nenhuma sessão foi criada.

---

## Caso 3: reutilização da transação

**Preparação:** login completo e bem-sucedido com Google, criando uma sessão válida.

**Pedido enviado:** a requisição de retorno (`GET /oauth/callback/google?code=...&state=...`) foi localizada no painel Network do navegador e reaberta uma segunda vez, após a conclusão do primeiro login.

**Resultado esperado:** como a transação já foi removida do D1 ao final do primeiro uso, a repetição deve falhar.

**Resultado observado:** a segunda tentativa respondeu com status 400 e a mensagem "Transação inválida ou expirada". Nenhuma sessão adicional foi criada.

---

## Caso 4: sessão expirada

**Preparação:** login completo e bem-sucedido, criando uma sessão válida reconhecida por `/api/me`.

**Pedido enviado:** no console do banco D1, executado:
```sql
UPDATE sessions
SET expires_at = 0;
```
Em seguida, a página foi recarregada.

**Resultado esperado:** `/api/me` deve responder 401, pois nenhuma sessão possui `expires_at` no futuro.

**Resultado observado:** `/api/me` respondeu com status 401 e `{"error":"unauthorized"}`. A página voltou a exibir "Nenhuma sessão neste navegador.".

---

## Caso 5: origem inválida na saída

**Preparação:** login completo e bem-sucedido, criando uma sessão válida.

**Pedido enviado:** em uma aba de outra origem (`https://example.com`), executado no console do navegador:
```js
fetch("https://avaliacao-2-ev8.pages.dev/oauth/logout", {
  method: "POST",
  credentials: "include"
});
```

**Resultado esperado:** a rota `/oauth/logout` recusa a operação por o cabeçalho `Origin` não corresponder a `PUBLIC_BASE_URL`; a sessão original permanece válida.

**Resultado observado:** a requisição não foi aceita pela rota de logout. Ao retornar à aba do site de produção, a sessão original continuava ativa, com o texto "Sessão de ..." ainda exibido — confirmando que o logout entre origens não foi efetivado.

---

## Caso 6: reutilização do cookie revogado

**Preparação:** login completo e bem-sucedido, criando uma sessão válida. O valor do cookie `__Host-session` foi copiado temporariamente pelas ferramentas de desenvolvedor.

**Pedido enviado:** logout executado pelo botão "Sair". Em seguida, o valor do cookie `__Host-session` copiado anteriormente foi restaurado manualmente pelas ferramentas de desenvolvedor, e `/api/me` foi consultado novamente.

**Resultado esperado:** como a linha correspondente foi removida do D1 no logout, a resposta deve ser 401 mesmo com o cookie restaurado.

**Resultado observado:** `/api/me` respondeu com status 401 e `{"error":"unauthorized"}`. A cópia do valor do cookie foi apagada imediatamente após o teste.

---

## Resumo

| Caso | Resultado esperado | Resultado observado |
|---|---|---|
| 1. Sem cookie temporário | Recusado | ✅ Recusado (400) |
| 2. State alterado | Recusado | ✅ Recusado (400) |
| 3. Reutilização da transação | Recusado | ✅ Recusado (400) |
| 4. Sessão expirada | 401 | ✅ 401 |
| 5. Origem inválida no logout | Recusado, sessão preservada | ✅ Recusado, sessão preservada |
| 6. Cookie revogado reutilizado | 401 | ✅ 401 |
