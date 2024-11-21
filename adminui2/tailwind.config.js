/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.vue'],
  theme: {
    extend: {
      colors: {
        'primary-content': 'oklch(91.85% 0.041 287.86)'
      },
    },
  },
  plugins: [require('daisyui'), require('@tailwindcss/typography')],
  daisyui: {
    themes: [{
      corporate: {
        ...require('daisyui/src/theming/themes')['corporate'],
        'primary-content': 'oklch(91.85% 0.041 287.86)',
      }
    }]
  }
}
