/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/12/16 13:24:22 by novan-ve      #+#    #+#                 */
/*   Updated: 2022/05/26 13:39:55 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_printc(t_print *p)
{
	int		i;

	i = 0;
	p->tmplen++;
	if (p->just == 'r')
		ft_putchar_fd(va_arg(p->args, int), p->fd);
	while (i < (p->tmpwidth - 1))
	{
		ft_putchar_fd(p->padchar, p->fd);
		i++;
	}
	if (p->just == 'l')
		ft_putchar_fd(va_arg(p->args, int), p->fd);
}

void	ft_format2(t_print *p)
{
	p->i++;
	if (p->format[p->i] == '-' || p->format[p->i] == '.')
		ft_calcwidth(p);
	else if (p->format[p->i] >= '0' && p->format[p->i] <= '9')
		ft_calcwidth(p);
	else if (p->format[p->i] == '*')
		ft_calcwidth(p);
}

void	ft_format(t_print *p)
{
	ft_format2(p);
	if (p->format[p->i] == 's')
		ft_prints(p);
	else if (p->format[p->i] == 'i' || p->format[p->i] == 'd')
		ft_printi(p);
	else if (p->format[p->i] == 'c')
		ft_printc(p);
	else if (p->format[p->i] == 'p')
		ft_printp(p);
	else if (p->format[p->i] == 'u')
		ft_printu(p);
	else if (p->format[p->i] == '%')
		ft_printper(p);
	else if (p->format[p->i] == 'x')
		ft_printx(p, 0);
	else if (p->format[p->i] == 'X')
		ft_printx(p, 1);
	else
		p->error = 1;
}

void	ft_resetlst(t_print *p, int i)
{
	if (i == 0)
	{
		p->i = 0;
		p->len = 0;
		p->padchar = ' ';
		p->width = 0;
		p->tmpwidth = 0;
	}
	else if (i == 1)
	{
		p->i++;
		p->width += p->tmpwidth;
		p->tmpwidth = 0;
		p->len += p->tmplen;
	}
	p->tmplen = 0;
	p->error = 0;
	p->minus = 0;
	p->prec = -1;
	p->just = 'l';
}

int		ft_printf(const char *format, ...)
{
	t_print	p;

    p.fd = 1;
	ft_resetlst(&p, 0);
	p.format = (char*)format;
	va_start(p.args, format);
	while (p.format[p.i] != '\0')
	{
		if (p.format[p.i] == '%')
			ft_format(&p);
		else
		{
			ft_putchar_fd(p.format[p.i], p.fd);
			p.len++;
		}
		if (p.error == 1)
			return (-1);
		ft_resetlst(&p, 1);
		if (p.len < p.width)
			p.len = p.width;
	}
	va_end(p.args);
	return (p.len);
}

int		ft_dprintf(int fd, const char *format, ...)
{
	t_print	p;

    p.fd = fd;
	ft_resetlst(&p, 0);
	p.format = (char*)format;
	va_start(p.args, format);
	while (p.format[p.i] != '\0')
	{
		if (p.format[p.i] == '%')
			ft_format(&p);
		else
		{
			ft_putchar_fd(p.format[p.i], p.fd);
			p.len++;
		}
		if (p.error == 1)
			return (-1);
		ft_resetlst(&p, 1);
		if (p.len < p.width)
			p.len = p.width;
	}
	va_end(p.args);
	return (p.len);
}
