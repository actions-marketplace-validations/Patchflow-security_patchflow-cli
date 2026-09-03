// Angular safe fixture: using sanitizer.sanitize() for XSS prevention.
// The safe approach is to use sanitizer.sanitize() which properly sanitizes
// HTML without bypassing Angular's built-in protection.
import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-content',
  template: `<div [innerHTML]="safeContent"></div>`,
})
export class ContentComponent {
  safeContent: SafeHtml;

  constructor(private sanitizer: DomSanitizer) {
    // SAFE: sanitizer.sanitize() properly cleans HTML
    this.safeContent = this.sanitizer.sanitize(
      1, // SecurityContext.HTML
      '<p>Trusted content</p>'
    );
  }

  setContent(userInput: string): void {
    // SAFE: sanitizing before binding
    this.safeContent = this.sanitizer.sanitize(1, userInput);
  }
}
