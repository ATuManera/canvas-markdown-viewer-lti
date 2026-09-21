/**
 * Interface texts, in Spanish and English.
 *
 * A plain object rather than an i18n library: the catalogue is small, entirely static, and
 * needs no pluralisation rules or message syntax. Keeping it typed means a missing
 * translation is a compile error rather than a string that shows a key to a student.
 */

export const LOCALES = ['es', 'en'] as const;
export type Locale = (typeof LOCALES)[number];

export interface Messages {
  readonly appName: string;
  readonly appTagline: string;

  readonly relayTitle: string;
  readonly relayContinue: string;
  readonly verifyTitle: string;
  readonly verifyChecking: string;
  readonly verifyMismatch: string;

  readonly authorizeTitle: string;
  readonly authorizeExplanation: string;
  readonly authorizeScopes: string;
  readonly authorizeButton: string;
  readonly authorizeFullWindow: string;
  readonly authorizeFullWindowHint: string;
  readonly authorizeDenied: string;

  readonly pickerTitle: string;
  readonly pickerWhyTitle: string;
  readonly pickerWhy: string;
  readonly pickerSearchLabel: string;
  readonly pickerSearchButton: string;
  readonly pickerEmpty: string;
  readonly pickerEmptySearch: string;
  readonly pickerMarkdownGroup: string;
  readonly pickerOtherGroup: string;
  readonly pickerOpen: string;
  readonly pickerLastOpened: string;
  readonly pickerColumnName: string;
  readonly pickerColumnFolder: string;
  readonly pickerColumnSize: string;
  readonly pickerColumnUpdated: string;

  readonly viewerBack: string;
  readonly viewerDownload: string;
  readonly viewerTheme: string;
  readonly viewerThemeLight: string;
  readonly viewerThemeDark: string;
  readonly viewerThemeSystem: string;
  readonly viewerExternalImagesBlocked: string;
  readonly viewerExternalLink: string;
  readonly viewerSignOut: string;

  readonly errorTitle: string;
  readonly errorGeneric: string;
  readonly errorLaunch: string;
  readonly errorNotAuthorized: string;
  readonly errorNotFound: string;
  readonly errorForbidden: string;
  readonly errorNotMarkdown: string;
  readonly errorTooLarge: string;
  readonly errorUnreadable: string;
  readonly errorTooComplex: string;
  readonly errorNoCourse: string;
  readonly errorReference: string;

  readonly independenceNotice: string;
}

const es: Messages = {
  appName: 'Visor de Markdown',
  appTagline: 'Visor de archivos Markdown para Canvas LMS',

  relayTitle: 'Conectando con Canvas…',
  relayContinue: 'Continuar',
  verifyTitle: 'Comprobando el lanzamiento',
  verifyChecking: 'Comprobando el lanzamiento…',
  verifyMismatch: 'No se pudo verificar este lanzamiento. Vuelve a abrir el archivo desde Canvas.',

  authorizeTitle: 'Autorizar el acceso a tus archivos',
  authorizeExplanation:
    'Para mostrarte un archivo Markdown, esta herramienta necesita leerlo en Canvas en tu nombre. Solo verá los archivos que tú ya puedes ver.',
  authorizeScopes: 'Permisos solicitados: leer la lista de archivos del curso y descargarlos.',
  authorizeButton: 'Autorizar en Canvas',
  authorizeFullWindow: 'Abrir en ventana completa',
  authorizeFullWindowHint:
    'Úsalo si la autorización no se muestra correctamente dentro de esta ventana.',
  authorizeDenied:
    'No se concedió la autorización. Sin ella, la herramienta no puede leer tus archivos.',

  pickerTitle: 'Elige un archivo Markdown',
  pickerWhyTitle: '¿Por qué hay que elegir el archivo?',
  pickerWhy:
    'Canvas no comunica a las herramientas LTI 1.3 cuál es el archivo desde el que se abrió el menú. Por eso mostramos aquí los archivos que puedes ver.',
  pickerSearchLabel: 'Buscar por nombre',
  pickerSearchButton: 'Buscar',
  pickerEmpty: 'No hay archivos Markdown en este curso a los que tengas acceso.',
  pickerEmptySearch: 'Ningún archivo coincide con la búsqueda.',
  pickerMarkdownGroup: 'Archivos Markdown',
  pickerOtherGroup: 'Otros archivos del curso',
  pickerOpen: 'Abrir',
  pickerLastOpened: 'Último abierto en esta sesión',
  pickerColumnName: 'Nombre',
  pickerColumnFolder: 'Carpeta',
  pickerColumnSize: 'Tamaño',
  pickerColumnUpdated: 'Modificado',

  viewerBack: 'Volver a la lista',
  viewerDownload: 'Descargar el original',
  viewerTheme: 'Tema',
  viewerThemeLight: 'Claro',
  viewerThemeDark: 'Oscuro',
  viewerThemeSystem: 'Según el sistema',
  viewerExternalImagesBlocked:
    'Se ha bloqueado una imagen alojada fuera de Canvas para no revelar tus datos de navegación.',
  viewerExternalLink: 'Se abre en una pestaña nueva',
  viewerSignOut: 'Revocar el acceso',

  errorTitle: 'No se pudo completar la operación',
  errorGeneric: 'Algo no ha funcionado. Vuelve a intentarlo desde Canvas.',
  errorLaunch: 'No se pudo validar el lanzamiento desde Canvas. Vuelve a abrir el archivo.',
  errorNotAuthorized: 'Necesitas autorizar el acceso a tus archivos antes de continuar.',
  errorNotFound: 'El archivo no existe o no está en este curso.',
  errorForbidden: 'No tienes permiso para ver este archivo.',
  errorNotMarkdown: 'Este archivo no es Markdown, así que no se puede mostrar aquí.',
  errorTooLarge: 'El archivo supera el tamaño máximo configurado.',
  errorUnreadable: 'El archivo no parece texto legible.',
  errorTooComplex: 'El documento es demasiado extenso o complejo para mostrarlo.',
  errorNoCourse: 'Esta herramienta debe abrirse desde los archivos de un curso.',
  errorReference: 'Referencia para soporte',

  independenceNotice:
    'Canvas LMS es una marca registrada de Instructure, Inc. Este proyecto independiente no está afiliado a Instructure, ni patrocinado ni respaldado por ella.',
};

const en: Messages = {
  appName: 'Markdown Viewer',
  appTagline: 'Markdown file viewer for Canvas LMS',

  relayTitle: 'Connecting to Canvas…',
  relayContinue: 'Continue',
  verifyTitle: 'Checking the launch',
  verifyChecking: 'Checking the launch…',
  verifyMismatch: 'This launch could not be verified. Please open the file from Canvas again.',

  authorizeTitle: 'Authorise access to your files',
  authorizeExplanation:
    'To show you a Markdown file, this tool needs to read it from Canvas on your behalf. It will only ever see files you can already see.',
  authorizeScopes: 'Permissions requested: list the course files and download them.',
  authorizeButton: 'Authorise in Canvas',
  authorizeFullWindow: 'Open in a full window',
  authorizeFullWindowHint: 'Use this if the authorisation screen does not display here.',
  authorizeDenied: 'Authorisation was not granted. Without it, the tool cannot read your files.',

  pickerTitle: 'Choose a Markdown file',
  pickerWhyTitle: 'Why do I have to choose the file?',
  pickerWhy:
    'Canvas does not tell LTI 1.3 tools which file the menu was opened from. That is why the files you can see are listed here.',
  pickerSearchLabel: 'Search by name',
  pickerSearchButton: 'Search',
  pickerEmpty: 'There are no Markdown files in this course that you can access.',
  pickerEmptySearch: 'No file matches that search.',
  pickerMarkdownGroup: 'Markdown files',
  pickerOtherGroup: 'Other course files',
  pickerOpen: 'Open',
  pickerLastOpened: 'Last opened in this session',
  pickerColumnName: 'Name',
  pickerColumnFolder: 'Folder',
  pickerColumnSize: 'Size',
  pickerColumnUpdated: 'Updated',

  viewerBack: 'Back to the list',
  viewerDownload: 'Download the original',
  viewerTheme: 'Theme',
  viewerThemeLight: 'Light',
  viewerThemeDark: 'Dark',
  viewerThemeSystem: 'Match the system',
  viewerExternalImagesBlocked:
    'An image hosted outside Canvas was blocked, so that your browsing details are not disclosed.',
  viewerExternalLink: 'Opens in a new tab',
  viewerSignOut: 'Revoke access',

  errorTitle: 'That did not work',
  errorGeneric: 'Something went wrong. Please try again from Canvas.',
  errorLaunch: 'The launch from Canvas could not be validated. Please open the file again.',
  errorNotAuthorized: 'You need to authorise access to your files before continuing.',
  errorNotFound: 'That file does not exist, or is not in this course.',
  errorForbidden: 'You do not have permission to view that file.',
  errorNotMarkdown: 'That file is not Markdown, so it cannot be shown here.',
  errorTooLarge: 'The file is larger than the configured limit.',
  errorUnreadable: 'The file does not appear to be readable text.',
  errorTooComplex: 'The document is too long or too complex to display.',
  errorNoCourse: 'This tool has to be opened from the files of a course.',
  errorReference: 'Support reference',

  independenceNotice:
    'Canvas LMS is a trademark of Instructure, Inc. This independent project is not affiliated with, sponsored by, or endorsed by Instructure.',
};

const CATALOGUES: Record<Locale, Messages> = { es, en };

export function messagesFor(locale: Locale): Messages {
  return CATALOGUES[locale];
}

/**
 * Picks a locale from the LTI `launch_presentation.locale` claim, which Canvas fills from
 * the user's own Canvas preference. An unknown or absent value falls back to the operator's
 * default rather than to English: an institution's students are better served by its own
 * language than by the project's.
 */
export function negotiateLocale(claimed: string | undefined, fallback: Locale): Locale {
  if (!claimed) return fallback;
  const primary = claimed.toLowerCase().split(/[-_]/)[0];
  return (LOCALES as readonly string[]).includes(primary ?? '') ? (primary as Locale) : fallback;
}

/** Formats a byte count for display, in the conventions of the chosen language. */
export function formatBytes(bytes: number, locale: Locale): string {
  const units = ['B', 'kB', 'MB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const formatted = new Intl.NumberFormat(locale === 'es' ? 'es-ES' : 'en-GB', {
    maximumFractionDigits: value < 10 && unit > 0 ? 1 : 0,
  }).format(value);
  return `${formatted} ${units[unit] ?? 'B'}`;
}

/** Formats an ISO timestamp for display, or returns undefined when there is none. */
export function formatDate(iso: string | undefined, locale: Locale): string | undefined {
  if (!iso) return undefined;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return undefined;
  return new Intl.DateTimeFormat(locale === 'es' ? 'es-ES' : 'en-GB', {
    dateStyle: 'medium',
  }).format(date);
}
