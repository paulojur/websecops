import { useLanguage as useLanguageContext } from './LanguageContext';

export function useLanguage() {
  return useLanguageContext();
}
