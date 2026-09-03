// Angular vulnerable fixture: bypassSecurityTrustHtml with route data.
// PF-ANGULAR-XSS-001 (pattern) should fire on bypassSecurityTrustHtml with
// route.queryParams. JS029 (pattern) should fire on bypassSecurityTrustHtml.
import { Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-content',
  template: `<div [innerHTML]="content"></div>`,
})
export class ContentComponent {
  content: SafeHtml;

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    // VULNERABLE: route data flows to bypassSecurityTrustHtml without sanitization
    const userInput = this.route.snapshot.queryParams['html'];
    this.content = this.sanitizer.bypassSecurityTrustHtml(userInput);
  }
}
