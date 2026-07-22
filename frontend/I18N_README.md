# Sistema de Internacionalização (i18n) - WebSecOps

## 🌍 Visão Geral

O WebSecOps agora possui suporte completo para múltiplos idiomas com detecção automática. O sistema detecta o idioma do navegador (PT ou EN) e mantém a preferência do usuário armazenada.

## 🚀 Como Funciona

### 1. **Detecção Automática de Idioma**
   - Ao acessar o site pela primeira vez, o sistema detecta o idioma do navegador
   - Se o navegador estiver em Português, exibe em PT
   - Se estiver em outra língua (ou EN), exibe em EN
   - A preferência é salva no `localStorage`

### 2. **Seletor de Idioma**
   - Localizado na Sidebar, abaixo do menu de navegação
   - Botões **PT** e **EN** para alternar entre idiomas
   - A preferência é persistida ao recarregar a página

### 3. **Arquivos Principais**

#### `lib/i18n.ts`
- Define todas as traduções disponíveis (PT e EN)
- Contém a função `detectLanguage()` para auto-detectar o idioma
- Exporta a função `getTranslation()` para buscar traduções

#### `lib/LanguageContext.tsx`
- Provedor React Context para gerenciar o estado do idioma
- Detecta o idioma ao montar o componente
- Oferece a função `setLanguage()` para trocar idiomas

#### `lib/useLanguage.ts`
- Hook customizado para acessar o contexto de idioma
- Retorna: `{ language, setLanguage, t }`

#### `app/layout.tsx`
- Envolve toda a aplicação com `<LanguageProvider>`
- Permite que todos os componentes acessem o idioma

### 4. **Como Usar nos Componentes**

#### Exemplo de uso básico:
```tsx
'use client';

import { useLanguage } from '@/lib/useLanguage';

export default function MinhaComponente() {
  const { t, language, setLanguage } = useLanguage();

  return (
    <div>
      <h1>{t('dashboard')}</h1>
      <p>Idioma atual: {language}</p>
      <button onClick={() => setLanguage('pt')}>Português</button>
      <button onClick={() => setLanguage('en')}>English</button>
    </div>
  );
}
```

## 📝 Chaves de Tradução Disponíveis

As seguintes chaves podem ser usadas com a função `t()`:

### Sidebar
- `dashboard` - Dashboard
- `myTargets` - Meus Alvos
- `scanCenter` - Centro de Scan
- `vulnerabilities` - Vulnerabilidades
- `intelligence` - Inteligência
- `qaEngineer` - Engenheiro de QA
- `securityDept` - Departamento de Segurança
- `language` - Idioma

### Dashboard/Home
- `trackedAssets` - Ativos Rastreados
- `criticalVulnerabilities` - Vulnerabilidades Críticas
- `recentVulnerabilities` - Vulnerabilidades Recentes
- `threatIntelligence` - Inteligência de Ameaças
- `targetCorrelations` - Correlações de Alvos
- `severity` - Severidade
- `critical`, `high`, `medium`, `low` - Níveis de severidade
- `addTarget` - Adicionar Alvo
- `addButton` - Adicionar
- `noTargets` - Nenhum alvo encontrado
- `loadingData` - Carregando dados...
- `noCVEFound` - Nenhum CVE encontrado
- `lastScanned` - Último Scan
- `syncVulnerabilities` - Sincronizar Vulnerabilidades
- `areYouSure` - Tem certeza de que deseja deletar este alvo?

## 🔧 Adicionando Novas Traduções

Para adicionar uma nova chave de tradução:

1. Abra `lib/i18n.ts`
2. Adicione a chave em ambas as versões (PT e EN):

```typescript
export const translations = {
  pt: {
    // ... outras chaves
    minhaNovaChave: 'Texto em Português',
  },
  en: {
    // ... outras chaves
    minhaNovaChave: 'Text in English',
  },
};
```

3. Use a chave no seu componente:
```tsx
const { t } = useLanguage();
<p>{t('minhaNovaChave')}</p>
```

## 🌐 Detalhes Técnicos

### Armazenamento de Preferência
- A preferência de idioma é salva em `localStorage` com a chave `language`
- Formato: `'pt'` ou `'en'`
- Persiste entre sessões do navegador

### Fluxo de Detecção
1. Verifica se existe idioma salvo em `localStorage`
2. Se sim, usa a preferência salva
3. Se não, detecta o idioma do navegador (`navigator.language`)
4. Retorna `'pt'` para português, caso contrário retorna `'en'`

### Atualização do HTML
- O atributo `lang` do `<html>` é atualizado quando o idioma muda
- Isso ajuda com SEO e acessibilidade

## 📱 Responsividade

O seletor de idioma é totalmente responsivo:
- Fica visível na Sidebar em todas as resoluções
- Botões com feedback visual (destaque quando selecionado)
- Animações suaves ao trocar de idioma

## ✅ Checklist de Implementação

- ✅ Sistema de detecção automática de idioma
- ✅ Armazenamento de preferência do usuário
- ✅ Seletor de idioma na Sidebar
- ✅ Traduções básicas (PT/EN)
- ✅ Componentes atualizados (Home, Sidebar)
- ✅ Hook `useLanguage()` para fácil acesso
- ✅ Contexto Provider no Layout
- ⏳ Traduções completas de todas as páginas (Targets, Scans, Vulnerabilidades, Intelligence)

## 🎯 Próximos Passos

Para adicionar mais traduções:
1. Adicione as novas chaves em `lib/i18n.ts`
2. Atualize componentes das páginas (targets, scans, vulns, intelligence)
3. Teste em ambos os idiomas

## 🐛 Troubleshooting

### O idioma não está salvando?
- Verifique se o localStorage está habilitado no navegador
- Limpe o cache do navegador

### Vejo strings em inglês que deveriam estar em português?
- Verifique se a chave de tradução foi adicionada a ambas as línguas
- Verifique se está usando a função `t()` corretamente

## 📞 Suporte

Para adicionar novas chaves de tradução, consulte o arquivo `lib/i18n.ts` e siga o padrão existente.
